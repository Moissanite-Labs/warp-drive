#!/usr/bin/env python3
"""R1-R5 unit and mutation-killing test suite for AUDIT-062 (warp-drive runtime & sandbox)."""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

_HERE = pathlib.Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import warp_drive_runtime_audit as mod  # noqa: E402


class TestStrictJsonAndSandbox(unittest.TestCase):
    def test_loads_strict_json(self) -> None:
        self.assertEqual(mod.loads_strict_json('{"a": 1, "b": 2}'), {"a": 1, "b": 2})
        with self.assertRaises(ValueError):
            mod.loads_strict_json('{"a": 1, "a": 2}')
        for bad in ("NaN", "Infinity", "-Infinity"):
            with self.assertRaises(ValueError):
                mod.loads_strict_json(f'{{"x": {bad}}}')

    def test_sandbox_invocation_gate(self) -> None:
        self.assertEqual(
            mod.validate_sandbox_invocation(
                bwrap_bin="/usr/bin/bwrap",
                worktree_real="/var/tmp/wt1",
                seccomp_enabled=True,
                landlock_enabled=True,
                required_env="0",
            ),
            (False, "sandbox_policy_disabled"),
        )
        self.assertEqual(
            mod.validate_sandbox_invocation(
                bwrap_bin="/tmp/fake/bwrap",
                worktree_real="/var/tmp/wt1",
                seccomp_enabled=True,
                landlock_enabled=True,
            ),
            (False, "untrusted_bwrap_path"),
        )
        self.assertEqual(
            mod.validate_sandbox_invocation(
                bwrap_bin="/usr/bin/bwrap",
                worktree_real="/var/tmp/wt1",
                seccomp_enabled=False,
                landlock_enabled=True,
            ),
            (False, "missing_kernel_isolation"),
        )
        self.assertEqual(
            mod.validate_sandbox_invocation(
                bwrap_bin="/usr/bin/bwrap",
                worktree_real="/var/tmp/wt1",
                seccomp_enabled=True,
                landlock_enabled=False,
            ),
            (False, "missing_kernel_isolation"),
        )
        self.assertEqual(
            mod.validate_sandbox_invocation(
                bwrap_bin="/usr/bin/bwrap",
                worktree_real="relative/wt",
                seccomp_enabled=True,
                landlock_enabled=True,
            ),
            (False, "non_absolute_worktree"),
        )
        # Rejects root, traversal, POSIX leading //, embedded //, dot segments, and NUL bytes
        self.assertEqual(
            mod.validate_sandbox_invocation(
                bwrap_bin="/usr/bin/bwrap",
                worktree_real="/var/tmp/wt\x00x",
                seccomp_enabled=True,
                landlock_enabled=True,
            ),
            (False, "non_absolute_worktree"),
        )
        for bad_noncanon in ("/", "//etc/warp/keys", "/var//tmp/wt", "/var/tmp/./wt", "/var/tmp/../etc"):
            self.assertEqual(
                mod.validate_sandbox_invocation(
                    bwrap_bin="/usr/bin/bwrap",
                    worktree_real=bad_noncanon,
                    seccomp_enabled=True,
                    landlock_enabled=True,
                ),
                (False, "unsafe_worktree_root_or_traversal"),
            )
        # Overlap both as subpath and as parent dir (/etc is parent of /etc/warp/keys)
        for bad_wt in ("/etc/warp/keys", "/etc/warp/keys/sub", "/etc", "/run/warp-modeld"):
            self.assertEqual(
                mod.validate_sandbox_invocation(
                    bwrap_bin="/usr/bin/bwrap",
                    worktree_real=bad_wt,
                    seccomp_enabled=True,
                    landlock_enabled=True,
                ),
                (False, "worktree_overlaps_explicit_deny"),
            )
        self.assertEqual(
            mod.validate_sandbox_invocation(
                bwrap_bin="/bin/bwrap",
                worktree_real="/var/tmp/worktree-1",
                seccomp_enabled=True,
                landlock_enabled=True,
            ),
            (True, "allow_sandbox_exec"),
        )


class TestStage1BindingAndFingerprint(unittest.TestCase):
    def test_loaded_adapter_binding(self) -> None:
        sha_a = "a" * 64
        sha_b = "b" * 64
        self.assertEqual(
            mod.verify_loaded_adapter_binding(
                bundle_llama_id=False,  # type: ignore[arg-type]
                bundle_adapter_sha256=sha_a,
                bundle_adapter_path=None,
                loaded_adapters={0: ("/a.gguf", sha_a)},
            ),
            (False, "invalid_bundle_llama_id"),
        )
        self.assertEqual(
            mod.verify_loaded_adapter_binding(
                bundle_llama_id=-1,
                bundle_adapter_sha256=sha_a,
                bundle_adapter_path=None,
                loaded_adapters={0: ("/a.gguf", sha_a)},
            ),
            (False, "invalid_bundle_llama_id"),
        )
        self.assertEqual(
            mod.verify_loaded_adapter_binding(
                bundle_llama_id=0,
                bundle_adapter_sha256="short",
                bundle_adapter_path=None,
                loaded_adapters={0: ("/a.gguf", sha_a)},
            ),
            (False, "invalid_bundle_sha256"),
        )
        self.assertEqual(
            mod.verify_loaded_adapter_binding(
                bundle_llama_id=1,
                bundle_adapter_sha256=sha_a,
                bundle_adapter_path=None,
                loaded_adapters={0: ("/a.gguf", sha_a)},
            ),
            (False, "adapter_id_not_loaded"),
        )
        self.assertEqual(
            mod.verify_loaded_adapter_binding(
                bundle_llama_id=0,
                bundle_adapter_sha256=sha_a,
                bundle_adapter_path=None,
                loaded_adapters={0: ("", sha_a)},
            ),
            (False, "missing_loaded_adapter_path"),
        )
        self.assertEqual(
            mod.verify_loaded_adapter_binding(
                bundle_llama_id=0,
                bundle_adapter_sha256=sha_a,
                bundle_adapter_path="/decoy.gguf",
                loaded_adapters={0: ("/real.gguf", sha_a)},
            ),
            (False, "adapter_path_mismatch"),
        )
        self.assertEqual(
            mod.verify_loaded_adapter_binding(
                bundle_llama_id=0,
                bundle_adapter_sha256=sha_a,
                bundle_adapter_path=None,
                loaded_adapters={0: ("/real.gguf", sha_b)},
            ),
            (False, "loaded_adapter_digest_mismatch"),
        )
        self.assertEqual(
            mod.verify_loaded_adapter_binding(
                bundle_llama_id=0,
                bundle_adapter_sha256=sha_a,
                bundle_adapter_path="/real.gguf",
                loaded_adapters={0: ("/real.gguf", sha_a)},
            ),
            (True, "loaded_adapter_verified"),
        )

    def test_checkpoint_lattice_dims_and_weft_flags(self) -> None:
        self.assertEqual(
            mod.validate_checkpoint_lattice_dims(
                has_horizontal_lattice="yes", lattice_layers=1, lattice_width=1  # type: ignore[arg-type]
            ),
            (False, "invalid_lattice_flag"),
        )
        self.assertEqual(
            mod.validate_checkpoint_lattice_dims(
                has_horizontal_lattice=True, lattice_layers=True, lattice_width=1  # type: ignore[arg-type]
            ),
            (False, "non_int_lattice_dims"),
        )
        self.assertEqual(
            mod.validate_checkpoint_lattice_dims(
                has_horizontal_lattice=True, lattice_layers=1, lattice_width=False  # type: ignore[arg-type]
            ),
            (False, "non_int_lattice_dims"),
        )
        self.assertEqual(
            mod.validate_checkpoint_lattice_dims(
                has_horizontal_lattice=True, lattice_layers=0, lattice_width=4
            ),
            (False, "lattice_dims_must_be_positive"),
        )
        self.assertEqual(
            mod.validate_checkpoint_lattice_dims(
                has_horizontal_lattice=True, lattice_layers=4, lattice_width=0
            ),
            (False, "lattice_dims_must_be_positive"),
        )
        self.assertEqual(
            mod.validate_checkpoint_lattice_dims(
                has_horizontal_lattice=True, lattice_layers=4, lattice_width=8
            ),
            (True, "lattice_dims_valid"),
        )
        self.assertEqual(
            mod.validate_checkpoint_lattice_dims(
                has_horizontal_lattice=False, lattice_layers=1, lattice_width=0
            ),
            (False, "lattice_dims_must_be_zero"),
        )
        self.assertEqual(
            mod.validate_checkpoint_lattice_dims(
                has_horizontal_lattice=False, lattice_layers=0, lattice_width=1
            ),
            (False, "lattice_dims_must_be_zero"),
        )
        self.assertEqual(
            mod.validate_checkpoint_lattice_dims(
                has_horizontal_lattice=False, lattice_layers=0, lattice_width=0
            ),
            (True, "non_lattice_dims_valid"),
        )

        flags_obj = {"ctx_size": 8192}
        flags_sha = mod.canonical_json_sha256(flags_obj)
        other_sha = "c" * 64
        self.assertEqual(
            mod.verify_weft_runtime_flags_binding({}, "bad"),
            (False, "invalid_caller_flags_sha256"),
        )
        self.assertEqual(
            mod.verify_weft_runtime_flags_binding({"runtime_flags": flags_obj}, flags_sha),
            (False, "missing_weft_runtime_flags_sha256"),
        )
        self.assertEqual(
            mod.verify_weft_runtime_flags_binding({"runtime_flags_sha256": "bad"}, flags_sha),
            (False, "invalid_weft_runtime_flags_sha256"),
        )
        self.assertEqual(
            mod.verify_weft_runtime_flags_binding({"runtime_flags_sha256": other_sha}, flags_sha),
            (False, "weft_runtime_flags_sha256_mismatch"),
        )
        self.assertEqual(
            mod.verify_weft_runtime_flags_binding(
                {"runtime_flags": "not-dict", "runtime_flags_sha256": flags_sha}, flags_sha
            ),
            (False, "invalid_weft_runtime_flags_obj"),
        )
        self.assertEqual(
            mod.verify_weft_runtime_flags_binding(
                {"runtime_flags": {"ctx_size": 1024}, "runtime_flags_sha256": flags_sha},
                flags_sha,
            ),
            (False, "weft_runtime_flags_internal_tamper"),
        )
        self.assertEqual(
            mod.verify_weft_runtime_flags_binding(
                {"runtime_flags": flags_obj, "runtime_flags_sha256": flags_sha}, flags_sha
            ),
            (True, "weft_runtime_flags_verified"),
        )
        self.assertEqual(
            mod.verify_weft_runtime_flags_binding({}, flags_sha),
            (True, "weft_runtime_flags_verified"),
        )


class TestStage3CanaryAndExternal(unittest.TestCase):
    def test_fenced_blocks_and_hardened_canary(self) -> None:
        prose, unclosed = mod.strip_closed_fenced_blocks(
            "Hello\n```py\nx; y\n```\nMiddle\n~~~\nz;\n~~~\nEnd"
        )
        self.assertEqual(prose, "Hello\nMiddle\nEnd")
        self.assertFalse(unclosed)
        prose_u, unclosed_u = mod.strip_closed_fenced_blocks("Hi\n```\nhidden;")
        self.assertEqual(prose_u, "Hi")
        self.assertTrue(unclosed_u)

        # Kills boundary & prose evasion bugs
        self.assertEqual(
            mod.evaluate_hardened_canary("1391", must_contain_tokens=("391",)),
            ["missing_token:391"],
        )
        self.assertEqual(
            mod.evaluate_hardened_canary("Note: yes", must_contain_tokens=("No",)),
            ["missing_token:No"],
        )
        self.assertEqual(
            mod.evaluate_hardened_canary("391", must_contain_tokens=("391",)),
            [],
        )
        self.assertEqual(
            mod.evaluate_hardened_canary("leak secret", must_not_contain=("secret",)),
            ["forbidden_substring:secret"],
        )
        self.assertEqual(
            mod.evaluate_hardened_canary(
                "```\ncode only;\n```", prose_only_forbid=(";",), min_prose_chars=5
            ),
            ["insufficient_prose_outside_fences"],
        )
        self.assertEqual(
            mod.evaluate_hardened_canary(
                "Plain prose; bad.", prose_only_forbid=(";",), min_prose_chars=5
            ),
            ["forbidden_prose:;"],
        )
        self.assertEqual(
            mod.evaluate_hardened_canary(
                "Clean prose.\n```js\nconst x = 1;\n```",
                prose_only_forbid=(";",),
                min_prose_chars=5,
            ),
            [],
        )
        # Exact boundary: len("12345") == 5 == min_prose_chars must pass (kills < vs <=)
        self.assertEqual(
            mod.evaluate_hardened_canary(
                "12345",
                prose_only_forbid=(";",),
                min_prose_chars=5,
            ),
            [],
        )

    def test_external_canary_payload_validator(self) -> None:
        sha = "a" * 64
        base_pres = [
            {"canary_id": f"p{i}", "category": "preservation", "passed": True, "failures": []}
            for i in range(2)
        ]
        dom_ok = {"canary_id": "d1", "category": "domain", "domain": "corpus", "passed": True, "failures": []}
        cross_ok = {"canary_id": "x1", "category": "cross_adapter", "passed": True, "failures": []}

        self.assertEqual(
            mod.validate_external_canary_payload("{bad", expected_suite_sha256=sha, required_domains=(), min_preservation=1),
            (False, "invalid_or_duplicate_json"),
        )
        self.assertEqual(
            mod.validate_external_canary_payload('{"a":1,"a":2}', expected_suite_sha256=sha, required_domains=(), min_preservation=1),
            (False, "invalid_or_duplicate_json"),
        )
        self.assertEqual(
            mod.validate_external_canary_payload("[]", expected_suite_sha256=sha, required_domains=(), min_preservation=1),
            (False, "payload_not_object"),
        )
        self.assertEqual(
            mod.validate_external_canary_payload(json.dumps({"suite_sha256": "wrong"}), expected_suite_sha256=sha, required_domains=(), min_preservation=1),
            (False, "suite_sha256_mismatch"),
        )
        self.assertEqual(
            mod.validate_external_canary_payload(json.dumps({"suite_sha256": sha, "outcomes": []}), expected_suite_sha256=sha, required_domains=(), min_preservation=1),
            (False, "missing_outcomes_list"),
        )
        self.assertEqual(
            mod.validate_external_canary_payload(json.dumps({"suite_sha256": sha, "outcomes": ["bad"]}), expected_suite_sha256=sha, required_domains=(), min_preservation=1),
            (False, "malformed_outcome_item"),
        )
        self.assertEqual(
            mod.validate_external_canary_payload(
                json.dumps({"suite_sha256": sha, "outcomes": [base_pres[0], base_pres[0]]}),
                expected_suite_sha256=sha,
                required_domains=(),
                min_preservation=1,
            ),
            (False, "invalid_or_duplicate_canary_id"),
        )
        self.assertEqual(
            mod.validate_external_canary_payload(
                json.dumps({"suite_sha256": sha, "outcomes": [{"canary_id": "p0", "category": "preservation", "passed": 1, "failures": []}]}),
                expected_suite_sha256=sha,
                required_domains=(),
                min_preservation=1,
            ),
            (False, "invalid_outcome_fields"),
        )
        self.assertEqual(
            mod.validate_external_canary_payload(
                json.dumps({"suite_sha256": sha, "outcomes": [{"canary_id": "p0", "category": "preservation", "passed": True, "failures": ["ERR"]}]}),
                expected_suite_sha256=sha,
                required_domains=(),
                min_preservation=1,
            ),
            (False, "contradictory_pass_with_failures"),
        )
        self.assertEqual(
            mod.validate_external_canary_payload(
                json.dumps({"suite_sha256": sha, "outcomes": [{"canary_id": "p0", "category": "preservation", "passed": False, "failures": ["ERR"]}]}),
                expected_suite_sha256=sha,
                required_domains=(),
                min_preservation=1,
            ),
            (False, "canary_failed"),
        )
        self.assertEqual(
            mod.validate_external_canary_payload(
                json.dumps({"suite_sha256": sha, "outcomes": [{"canary_id": "d1", "category": "domain", "passed": True, "failures": []}]}),
                expected_suite_sha256=sha,
                required_domains=("corpus",),
                min_preservation=0,
            ),
            (False, "domain_canary_missing_domain"),
        )
        self.assertEqual(
            mod.validate_external_canary_payload(
                json.dumps({"suite_sha256": sha, "outcomes": [{"canary_id": "u1", "category": "unknown", "passed": True, "failures": []}]}),
                expected_suite_sha256=sha,
                required_domains=(),
                min_preservation=0,
            ),
            (False, "unknown_canary_category"),
        )
        # Float or mismatched preservation_total rejected
        self.assertEqual(
            mod.validate_external_canary_payload(
                json.dumps({"suite_sha256": sha, "preservation_total": 2.0, "outcomes": base_pres}),
                expected_suite_sha256=sha,
                required_domains=(),
                min_preservation=2,
            ),
            (False, "inconsistent_preservation_total"),
        )
        self.assertEqual(
            mod.validate_external_canary_payload(
                json.dumps({"suite_sha256": sha, "preservation_passed": 1, "outcomes": base_pres}),
                expected_suite_sha256=sha,
                required_domains=(),
                min_preservation=2,
            ),
            (False, "inconsistent_preservation_passed"),
        )
        self.assertEqual(
            mod.validate_external_canary_payload(
                json.dumps({"suite_sha256": sha, "outcomes": base_pres}),
                expected_suite_sha256=sha,
                required_domains=(),
                min_preservation=3,
            ),
            (False, "insufficient_preservation_canaries"),
        )
        self.assertEqual(
            mod.validate_external_canary_payload(
                json.dumps({"suite_sha256": sha, "outcomes": base_pres}),
                expected_suite_sha256=sha,
                required_domains=("corpus",),
                min_preservation=2,
            ),
            (False, "missing_domain_coverage:corpus"),
        )
        self.assertEqual(
            mod.validate_external_canary_payload(
                json.dumps({"suite_sha256": sha, "passed": False, "outcomes": base_pres + [dom_ok]}),
                expected_suite_sha256=sha,
                required_domains=("corpus",),
                min_preservation=2,
            ),
            (False, "top_level_verdict_failed"),
        )
        self.assertEqual(
            mod.validate_external_canary_payload(
                json.dumps({"suite_sha256": sha, "all_passed": False, "outcomes": base_pres + [dom_ok]}),
                expected_suite_sha256=sha,
                required_domains=("corpus",),
                min_preservation=2,
            ),
            (False, "top_level_verdict_failed"),
        )
        self.assertEqual(
            mod.validate_external_canary_payload(
                json.dumps({"suite_sha256": sha, "verdict": "reject", "outcomes": base_pres + [dom_ok]}),
                expected_suite_sha256=sha,
                required_domains=("corpus",),
                min_preservation=2,
            ),
            (False, "top_level_verdict_failed"),
        )
        self.assertEqual(
            mod.validate_external_canary_payload(
                json.dumps({"suite_sha256": sha, "passed": True, "all_passed": True, "verdict": "pass", "preservation_total": 2, "preservation_passed": 2, "outcomes": base_pres + [dom_ok, cross_ok]}),
                expected_suite_sha256=sha,
                required_domains=("corpus",),
                min_preservation=2,
            ),
            (True, "external_canary_verified"),
        )


class TestStage4FlushCommitLedgerAndRpc(unittest.TestCase):
    def test_multi_bank_flush_and_atomic_commit(self) -> None:
        clean = {"tainted": False, "active_lora_ids": [], "tokens_or_layers": 0}
        self.assertEqual(
            mod.verify_multi_bank_flush(
                required_banks=(),
                erase_confirmed=(),
                slot_banks={},
            ),
            (False, "empty_required_banks"),
        )
        self.assertEqual(
            mod.verify_multi_bank_flush(
                required_banks=("kv_cache",),
                erase_confirmed=("kv_cache",),
                slot_banks={"kv_cache": {"tainted": False}},
            ),
            (False, "bank_missing_active_lora_ids:kv_cache"),
        )
        self.assertEqual(
            mod.verify_multi_bank_flush(
                required_banks=("kv_cache",),
                erase_confirmed=("kv_cache",),
                slot_banks={"kv_cache": {"tainted": False, "active_lora_ids": []}},
            ),
            (False, "bank_missing_tokens_or_layers:kv_cache"),
        )
        self.assertEqual(
            mod.verify_multi_bank_flush(
                required_banks=("kv_cache", "ssm_recurrent"),
                erase_confirmed=("kv_cache",),
                slot_banks={"kv_cache": clean, "ssm_recurrent": clean},
            ),
            (False, "missing_bank_confirmation:ssm_recurrent"),
        )
        self.assertEqual(
            mod.verify_multi_bank_flush(
                required_banks=("kv_cache", "ssm_recurrent"),
                erase_confirmed=("kv_cache", "ssm_recurrent"),
                slot_banks={"kv_cache": clean},
            ),
            (False, "missing_slot_bank_status:ssm_recurrent"),
        )
        self.assertEqual(
            mod.verify_multi_bank_flush(
                required_banks=("ssm_recurrent",),
                erase_confirmed=("ssm_recurrent",),
                slot_banks={"ssm_recurrent": {"tainted": True, "active_lora_ids": [], "tokens_or_layers": 0}},
            ),
            (False, "bank_retained_taint:ssm_recurrent"),
        )
        self.assertEqual(
            mod.verify_multi_bank_flush(
                required_banks=("ssm_recurrent",),
                erase_confirmed=("ssm_recurrent",),
                slot_banks={"ssm_recurrent": {"tainted": False, "active_lora_ids": [0], "tokens_or_layers": 0}},
            ),
            (False, "bank_retained_lora_ids:ssm_recurrent"),
        )
        self.assertEqual(
            mod.verify_multi_bank_flush(
                required_banks=("ssm_recurrent",),
                erase_confirmed=("ssm_recurrent",),
                slot_banks={"ssm_recurrent": {"tainted": False, "active_lora_ids": [], "tokens_or_layers": 3}},
            ),
            (False, "bank_retained_tokens:ssm_recurrent"),
        )
        self.assertEqual(
            mod.verify_multi_bank_flush(
                required_banks=("kv_cache", "ssm_recurrent"),
                erase_confirmed=("kv_cache", "ssm_recurrent"),
                slot_banks={"kv_cache": clean, "ssm_recurrent": clean},
            ),
            (True, "all_required_banks_clean"),
        )

        self.assertEqual(
            mod.atomic_mount_commit_model(set_lora_ok=False, ledger_append_ok=True, rollback_on_failure_ok=True)["state"],
            "quarantined_activation_error",
        )
        self.assertEqual(
            mod.atomic_mount_commit_model(set_lora_ok=True, ledger_append_ok=False, rollback_on_failure_ok=True)["state"],
            "rolled_back_and_quarantined",
        )
        self.assertEqual(
            mod.atomic_mount_commit_model(set_lora_ok=True, ledger_append_ok=False, rollback_on_failure_ok=False)["state"],
            "quarantined_rollback_failed",
        )
        self.assertEqual(
            mod.atomic_mount_commit_model(set_lora_ok=True, ledger_append_ok=True, rollback_on_failure_ok=True)["state"],
            "committed_logged",
        )

    def test_strict_jsonl_ledger(self) -> None:
        self.assertEqual(mod.verify_strict_jsonl_ledger(""), (True, "empty_genesis_ledger"))
        self.assertEqual(
            mod.verify_strict_jsonl_ledger("", expected_head_sha256="a" * 64),
            (False, "truncated_ledger_head_mismatch"),
        )
        self.assertEqual(mod.verify_strict_jsonl_ledger("  \n"), (False, "whitespace_only_tamper"))

        body1 = {"event": "mount"}
        sha1 = mod.canonical_json_sha256({"seq": 1, "prev_receipt_sha256": mod.GENESIS_HASH, "body": body1})
        rec1 = json.dumps({"seq": 1, "prev_receipt_sha256": mod.GENESIS_HASH, "body": body1, "receipt_sha256": sha1})

        body2 = {"event": "rollback"}
        sha2 = mod.canonical_json_sha256({"seq": 2, "prev_receipt_sha256": sha1, "body": body2})
        rec2 = json.dumps({"seq": 2, "prev_receipt_sha256": sha1, "body": body2, "receipt_sha256": sha2})

        self.assertEqual(mod.verify_strict_jsonl_ledger(f"{rec1}\n\n{rec2}"), (False, "unexpected_blank_line"))
        self.assertEqual(mod.verify_strict_jsonl_ledger('{"seq":1,"seq":1}'), (False, "invalid_or_duplicate_key_json"))
        self.assertEqual(mod.verify_strict_jsonl_ledger("[1,2]"), (False, "record_not_object"))
        # Reject extra smuggled top-level keys and missing required keys (BYPASS-02)
        self.assertEqual(
            mod.verify_strict_jsonl_ledger(
                json.dumps({"seq": 1, "prev_receipt_sha256": mod.GENESIS_HASH, "body": body1, "receipt_sha256": sha1, "signature": "FORGED"})
            ),
            (False, "unexpected_or_missing_record_keys"),
        )
        self.assertEqual(
            mod.verify_strict_jsonl_ledger(
                json.dumps({"seq": 1, "prev_receipt_sha256": mod.GENESIS_HASH, "body": body1})
            ),
            (False, "unexpected_or_missing_record_keys"),
        )
        self.assertEqual(
            mod.verify_strict_jsonl_ledger(json.dumps({"seq": True, "prev_receipt_sha256": mod.GENESIS_HASH, "body": body1, "receipt_sha256": sha1})),
            (False, "invalid_seq"),
        )
        self.assertEqual(
            mod.verify_strict_jsonl_ledger(json.dumps({"seq": 1, "prev_receipt_sha256": "1" * 64, "body": body1, "receipt_sha256": sha1})),
            (False, "broken_hash_chain"),
        )
        self.assertEqual(
            mod.verify_strict_jsonl_ledger(json.dumps({"seq": 1, "prev_receipt_sha256": mod.GENESIS_HASH, "body": "bad", "receipt_sha256": sha1})),
            (False, "missing_body_or_sha"),
        )
        self.assertEqual(
            mod.verify_strict_jsonl_ledger(json.dumps({"seq": 1, "prev_receipt_sha256": mod.GENESIS_HASH, "body": body1, "receipt_sha256": "f" * 64})),
            (False, "receipt_sha256_mismatch"),
        )
        self.assertEqual(
            mod.verify_strict_jsonl_ledger(f"{rec1}\n{rec2}\n", expected_head_sha256=sha1),
            (False, "head_anchor_mismatch"),
        )
        self.assertEqual(
            mod.verify_strict_jsonl_ledger(f"{rec1}\n{rec2}\n", expected_head_sha256=sha2),
            (True, "ledger_verified"),
        )

    def test_rpc_params_validator(self) -> None:
        self.assertEqual(
            mod.validate_rpc_params("warp_set_learning", {"enabled": True}, socket_mode=0o666),
            (False, "world_accessible_socket_mode"),
        )
        self.assertEqual(
            mod.validate_rpc_params("warp_set_learning", {"enabled": True}, socket_mode=-8),
            (False, "world_accessible_socket_mode"),
        )
        self.assertEqual(
            mod.validate_rpc_params("warp_set_learning", {"enabled": True}, socket_mode=0o1000),
            (False, "world_accessible_socket_mode"),
        )
        self.assertEqual(
            mod.validate_rpc_params("warp_set_learning", {"enabled": True}, socket_mode=0o770),
            (True, "rpc_params_valid"),
        )
        self.assertEqual(
            mod.validate_rpc_params("warp_infer", {"LORA": [], "messages": []}),
            (False, "unverified_lora_override"),
        )
        self.assertEqual(
            mod.validate_rpc_params("warp_infer", {"messages": "not-a-list"}),
            (False, "messages_must_be_list"),
        )
        self.assertEqual(
            mod.validate_rpc_params("warp_complete", {"prompt": 123}),
            (False, "prompt_must_be_str"),
        )
        self.assertEqual(
            mod.validate_rpc_params("warp_set_learning", {"enabled": "false"}),
            (False, "learning_enabled_must_be_strict_bool"),
        )
        self.assertEqual(
            mod.validate_rpc_params("warp_set_learning", {"enabled": False}),
            (True, "rpc_params_valid"),
        )
        self.assertEqual(
            mod.validate_rpc_params("wmcp_slot_mount", {"bundles": {}}),
            (False, "bundles_must_be_nonempty_list"),
        )
        self.assertEqual(
            mod.validate_rpc_params("wmcp_slot_mount", {"bundles": [{"id": 1}]}),
            (True, "rpc_params_valid"),
        )
        self.assertEqual(
            mod.validate_rpc_params("warp_infer", {"messages": [], "temperature": float("inf")}),
            (False, "non_finite_temperature"),
        )
        self.assertEqual(
            mod.validate_rpc_params("warp_infer", {"messages": [], "temperature": -1}),
            (False, "out_of_range_temperature"),
        )
        self.assertEqual(
            mod.validate_rpc_params("warp_infer", {"messages": [], "temperature": 3}),
            (False, "out_of_range_temperature"),
        )
        self.assertEqual(
            mod.validate_rpc_params("warp_complete", {"prompt": "ok", "top_p": 0, "temperature": 2, "seed": 0}),
            (True, "rpc_params_valid"),
        )
        self.assertEqual(
            mod.validate_rpc_params("warp_complete", {"prompt": "ok", "top_p": 1, "seed": True}),
            (False, "invalid_seed"),
        )
        self.assertEqual(
            mod.validate_rpc_params("warp_complete", {"prompt": "ok", "seed": -1}),
            (False, "invalid_seed"),
        )
        self.assertEqual(
            mod.validate_rpc_params("unknown_method", {}),
            (False, "unknown_rpc_method"),
        )

    def test_safe_llama_endpoint_ancestors_and_issue7_contract(self) -> None:
        self.assertFalse(mod.verify_safe_llama_endpoint(scheme="file", hostname="127.0.0.1", require_localhost=True, proxy_bypass_disabled=True, http_status=200))
        self.assertFalse(mod.verify_safe_llama_endpoint(scheme="http", hostname="evil.example", require_localhost=True, proxy_bypass_disabled=True, http_status=200))
        self.assertTrue(mod.verify_safe_llama_endpoint(scheme="https", hostname="remote.lan", require_localhost=False, proxy_bypass_disabled=True, http_status=200))
        self.assertFalse(mod.verify_safe_llama_endpoint(scheme="http", hostname="127.0.0.1", require_localhost=True, proxy_bypass_disabled=False, http_status=200))
        self.assertFalse(mod.verify_safe_llama_endpoint(scheme="http", hostname="127.0.0.1", require_localhost=True, proxy_bypass_disabled=True, http_status=300))
        self.assertFalse(mod.verify_safe_llama_endpoint(scheme="http", hostname="127.0.0.1", require_localhost=True, proxy_bypass_disabled=True, http_status=399))
        self.assertTrue(mod.verify_safe_llama_endpoint(scheme="http", hostname="127.0.0.1", require_localhost=True, proxy_bypass_disabled=True, http_status=299))
        self.assertTrue(mod.verify_safe_llama_endpoint(scheme="http", hostname="127.0.0.1", require_localhost=True, proxy_bypass_disabled=True, http_status=400))

        self.assertFalse(mod.verify_ancestor_dir_modes([]))
        self.assertFalse(mod.verify_ancestor_dir_modes([("/", 0o755), ("rel", 0o755)]))
        self.assertFalse(mod.verify_ancestor_dir_modes([("/", 0o755), ("/etc\x00", 0o755)]))
        self.assertFalse(mod.verify_ancestor_dir_modes([("/", 0o755), ("//etc", 0o755)]))
        self.assertFalse(mod.verify_ancestor_dir_modes([("/", 0o755), ("/etc/../var", 0o755)]))
        self.assertFalse(mod.verify_ancestor_dir_modes([("/", False)]))  # type: ignore[list-item]
        self.assertFalse(mod.verify_ancestor_dir_modes([("/", -1)]))
        self.assertFalse(mod.verify_ancestor_dir_modes([("/", 0o10000)]))
        self.assertFalse(mod.verify_ancestor_dir_modes([("/", 0o755), ("/", 0o755)]))
        self.assertFalse(mod.verify_ancestor_dir_modes([("/etc", 0o755)]))
        self.assertFalse(mod.verify_ancestor_dir_modes([("/", 0o755), ("/etc", 0o755), ("/etc/warp/canaries", 0o750)]))
        self.assertFalse(mod.verify_ancestor_dir_modes([("/", 0o755), ("/etc", 0o755), ("/etc/warp", 0o775)]))
        self.assertFalse(mod.verify_ancestor_dir_modes([("/", 0o755), ("/etc", 0o755), ("/etc/warp", 0o757)]))
        self.assertTrue(mod.verify_ancestor_dir_modes([("/", 0o000)]))
        self.assertTrue(mod.verify_ancestor_dir_modes([("/", 0o7755), ("/etc", 0o755), ("/etc/warp", 0o750)]))

        base = {
            "candidate_hash_recorded_before_eval": True,
            "split_overlap_count": 0,
            "repair_rounds_used": 3,
            "unchanged_base_control_passed": True,
            "regressed_plausible_text_rejected": True,
            "all_required_banks_flushed": True,
            "baseline_logits_restored": True,
            "ledger_receipts_complete": True,
            "signer_key_bytes": 16,
            "repair_confirmation": "12345678",
            "claim_status": "VERIFIED",
        }
        self.assertTrue(mod.verify_issue7_evidence_contract(base))
        self.assertTrue(mod.verify_issue7_evidence_contract({**base, "repair_rounds_used": 0, "repair_confirmation": None}))
        for patch in (
            {"candidate_hash_recorded_before_eval": False},
            {"split_overlap_count": 1},
            {"split_overlap_count": False},
            {"repair_rounds_used": -1},
            {"repair_rounds_used": 4},
            {"repair_rounds_used": True},
            {"unchanged_base_control_passed": False},
            {"regressed_plausible_text_rejected": False},
            {"all_required_banks_flushed": False},
            {"baseline_logits_restored": False},
            {"ledger_receipts_complete": False},
            {"signer_key_bytes": 15},
            {"signer_key_bytes": True},
            {"repair_confirmation": "1234567"},
            {"repair_confirmation": 12345678},
            {"claim_status": "INVENTED"},
        ):
            self.assertFalse(mod.verify_issue7_evidence_contract({**base, **patch}), f"expected False for {patch}")


class TestAnchorsAndSuite(unittest.TestCase):
    def _assert_no_floats(self, obj: object, path: str = "root") -> None:
        if isinstance(obj, float):
            self.fail(f"Forbidden float at {path}: {obj!r}")
        elif isinstance(obj, dict):
            for k, v in obj.items():
                self._assert_no_floats(v, f"{path}.{k}")
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                self._assert_no_floats(v, f"{path}[{i}]")

    def test_synthetic_anchors_and_full_suite(self) -> None:
        self.assertEqual(mod.count_bare_asserts("assert True\nx = 1\n"), 1)
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            self.assertEqual(
                mod.verify_warp_drive_anchors(root),
                {"mode": "standalone", "anchors_verified": 0},
            )
            src = root / "src" / "warp_modeld"
            src.mkdir(parents=True)
            sh = root / "blueprints" / "sandbox" / "warp-sandbox-exec.sh"
            sh.parent.mkdir(parents=True)
            sh.write_text("command -v bwrap\n", encoding="utf-8")
            (src / "fingerprint.py").write_text("if self.has_horizontal_lattice and layers <= 0:\n    pass\n", encoding="utf-8")
            (src / "canary.py").write_text('if line.lstrip().startswith("```"):\n    pass\nparsed = json.loads(proc.stdout)\nx = int(parsed["preservation_total"])\n', encoding="utf-8")
            (src / "verifier.py").write_text('if needs_lattice:\n    pass\nself._active_bundles = list(bundles)\nself.ledger.append(\n                "mount",\n)\n', encoding="utf-8")
            (src / "ledger.py").write_text("record = json.loads(raw_line)\nif not raw_text.strip():\n    pass\n", encoding="utf-8")
            (src / "server.py").write_text('enabled = bool(params["enabled"])\nos.chmod(self.socket_path, self.socket_mode)\n', encoding="utf-8")
            (src / "llama_client.py").write_text("urllib.request.urlopen(req)\n", encoding="utf-8")
            tests_d = root / "tests"
            tests_d.mkdir()
            (tests_d / "t.py").write_text("assert 1 == 1\n", encoding="utf-8")

            res = mod.verify_warp_drive_anchors(root)
            self.assertEqual(res["mode"], "live_read_only")
            self.assertEqual(res["anchors_verified"], 9)
            self.assertEqual(res["anchors_total"], 9)
            self.assertEqual(res["src_bare_asserts"], 0)
            self.assertEqual(res["test_bare_asserts"], 1)

        report = mod.run_audit_suite()
        self._assert_no_floats(report)
        self.assertEqual(report["audit_id"], "AUDIT-062")
        for key, passed in report["hardened_gates"].items():
            self.assertTrue(passed, f"gate failed: {key}")

        buf_json = io.StringIO()
        with contextlib.redirect_stdout(buf_json):
            rc_j = mod.main(["--json", "--standalone"])
        self.assertEqual(rc_j, 0)
        parsed = json.loads(buf_json.getvalue())
        self._assert_no_floats(parsed)
        self.assertEqual(parsed["live_read_only_anchors"]["mode"], "standalone")

        buf_txt = io.StringIO()
        with contextlib.redirect_stdout(buf_txt):
            rc_t = mod.main(["--standalone"])
        self.assertEqual(rc_t, 0)
        self.assertIn("AUDIT-062 PASS", buf_txt.getvalue())


if __name__ == "__main__":
    unittest.main()
