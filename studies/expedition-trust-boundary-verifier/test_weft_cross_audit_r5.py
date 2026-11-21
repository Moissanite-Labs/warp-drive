#!/usr/bin/env python3
"""Clean-room R5 mutation-killing unittest suite for weft_cross_audit_gate.py (AUDIT-065).

100% pure Python 3 stdlib; zero floats; zero bare asserts; targets 100.0% kill rate
under `aletheia v1.3.0 mutate --add-cwd`.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import sys
import unittest
from fractions import Fraction
from pathlib import Path

_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import weft_cross_audit_gate as wca  # noqa: E402


def _collect_floats(obj: object, path: str = "") -> list[str]:
    found: list[str] = []
    if isinstance(obj, float):
        found.append(path)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            found.extend(_collect_floats(v, f"{path}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found.extend(_collect_floats(v, f"{path}[{i}]"))
    return found


class TestWeftCrossAuditR5(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cert_live = wca.build_certificate(standalone=False)
        cls.cert_standalone = wca.build_certificate(standalone=True)

    def test_01_zero_floats_and_certificate_integrity(self) -> None:
        self.assertEqual(_collect_floats(self.cert_live), [])
        self.assertEqual(_collect_floats(self.cert_standalone), [])
        self.assertEqual(self.cert_live["audit_id"], "AUDIT-065")
        self.assertEqual(self.cert_live["honest_novelty_claim"], "N1")
        self.assertEqual(len(self.cert_live["findings_wd_x01_to_wd_x08"]), 8)

        with self.assertRaisesRegex(RuntimeError, "Missing certificate keys"):
            wca.verify_certificate_integrity({})
        bad_oracle = dict(self.cert_standalone, oracle_class="approx")
        with self.assertRaisesRegex(RuntimeError, "oracle_class"):
            wca.verify_certificate_integrity(bad_oracle)
        bad_r3 = copy.deepcopy(self.cert_standalone)
        bad_r3["hardened_cross_org_gates"]["r3_negative_controls"]["all_r3_rejected"] = False
        with self.assertRaisesRegex(RuntimeError, "R3 negative controls"):
            wca.verify_certificate_integrity(bad_r3)
        with self.assertRaisesRegex(RuntimeError, "verification failure"):
            wca._must(False, "forced")

    def test_02_strict_json_int_and_scale_guards(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-empty string"):
            wca.strict_loads_no_duplicate_keys("   ")
        with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
            wca.strict_loads_no_duplicate_keys('{"a":1,"a":2}')

        with self.assertRaisesRegex(TypeError, "exact int"):
            wca.require_strict_int(True, "x")
        with self.assertRaisesRegex(TypeError, "exact int"):
            wca.require_strict_int(1.0, "x")
        with self.assertRaisesRegex(ValueError, "below minimum"):
            wca.require_strict_int(-1, "x", min_val=0)
        with self.assertRaisesRegex(ValueError, "above maximum"):
            wca.require_strict_int(256, "x", min_val=0, max_val=255)
        self.assertEqual(wca.require_strict_int(0, "x", min_val=0, max_val=255), 0)
        self.assertEqual(wca.require_strict_int(255, "x", min_val=0, max_val=255), 255)

        with self.assertRaisesRegex(TypeError, "cannot be bool"):
            wca.parse_exact_nonneg_scale(False, "s")
        with self.assertRaisesRegex(TypeError, "decimal str"):
            wca.parse_exact_nonneg_scale(0.5, "s")
        with self.assertRaisesRegex(ValueError, "exact rational string"):
            wca.parse_exact_nonneg_scale("not_a_num", "s")
        with self.assertRaisesRegex(ValueError, "non-negative"):
            wca.parse_exact_nonneg_scale("-1/2", "s")
        self.assertEqual(wca.parse_exact_nonneg_scale(Fraction(0), "s"), Fraction(0))
        self.assertEqual(wca.parse_exact_nonneg_scale(2, "s"), Fraction(2))
        self.assertEqual(wca.parse_exact_nonneg_scale("0.4", "s"), Fraction(2, 5))

        with self.assertRaisesRegex(ValueError, "mapping"):
            wca.compute_zone_manifest_id_clean("bad")  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "non-empty"):
            wca.compute_zone_manifest_id_from_raw_json("")
        with self.assertRaisesRegex(ValueError, "JSON object"):
            wca.compute_zone_manifest_id_from_raw_json("[1,2]")

    def test_03_unified_zone_manifest_guards(self) -> None:
        zm, _ = wca._make_sample_mde_manifest()

        with self.assertRaisesRegex(ValueError, "JSON object"):
            wca.verify_zone_manifest_unified([])  # type: ignore[arg-type]
        bad_schema = dict(zm, schema="zone-manifest/v9")
        with self.assertRaisesRegex(ValueError, "schema"):
            wca.verify_zone_manifest_unified(bad_schema)
        bad_id_fmt = dict(zm, manifest_id="bad")
        with self.assertRaisesRegex(ValueError, "manifest_id format"):
            wca.verify_zone_manifest_unified(bad_id_fmt)
        tampered = copy.deepcopy(zm)
        tampered["zones"][0]["l1_bank_tag"] = 7
        with self.assertRaisesRegex(ValueError, "tamper"):
            wca.verify_zone_manifest_unified(tampered)

        empty_prec = copy.deepcopy(zm)
        empty_prec["precedence_order"] = []
        empty_prec["manifest_id"] = wca.compute_zone_manifest_id_clean(empty_prec)
        with self.assertRaisesRegex(ValueError, "precedence_order must be"):
            wca.verify_zone_manifest_unified(empty_prec)

        dup_prec = copy.deepcopy(zm)
        dup_prec["precedence_order"] = ["prose", "prose"]
        dup_prec["manifest_id"] = wca.compute_zone_manifest_id_clean(dup_prec)
        with self.assertRaisesRegex(ValueError, "duplicate zone names"):
            wca.verify_zone_manifest_unified(dup_prec)

        empty_zones = copy.deepcopy(zm)
        empty_zones["zones"] = []
        empty_zones["manifest_id"] = wca.compute_zone_manifest_id_clean(empty_zones)
        with self.assertRaisesRegex(ValueError, "zones must be"):
            wca.verify_zone_manifest_unified(empty_zones)

        bad_entry = copy.deepcopy(zm)
        bad_entry["zones"] = ["not_a_dict"]
        bad_entry["manifest_id"] = wca.compute_zone_manifest_id_clean(bad_entry)
        with self.assertRaisesRegex(ValueError, "Zone entry"):
            wca.verify_zone_manifest_unified(bad_entry)

        bad_zname = copy.deepcopy(zm)
        bad_zname["zones"][0]["zone"] = "bogus"
        bad_zname["manifest_id"] = wca.compute_zone_manifest_id_clean(bad_zname)
        with self.assertRaisesRegex(ValueError, "Unsupported zone name"):
            wca.verify_zone_manifest_unified(bad_zname)

        dup_zname = copy.deepcopy(zm)
        dup_zname["zones"][1]["zone"] = "formal_proof"
        dup_zname["manifest_id"] = wca.compute_zone_manifest_id_clean(dup_zname)
        with self.assertRaisesRegex(ValueError, "Duplicate zone name"):
            wca.verify_zone_manifest_unified(dup_zname)

        dup_tag = copy.deepcopy(zm)
        dup_tag["zones"][0]["l1_bank_tag"] = 0
        dup_tag["manifest_id"] = wca.compute_zone_manifest_id_clean(dup_tag)
        with self.assertRaisesRegex(ValueError, "Duplicate l1_bank_tag"):
            wca.verify_zone_manifest_unified(dup_tag)

        no_flags = copy.deepcopy(zm)
        no_flags["zones"][0]["protection_flags"] = {}
        no_flags["manifest_id"] = wca.compute_zone_manifest_id_clean(no_flags)
        with self.assertRaisesRegex(ValueError, "protection_flags"):
            wca.verify_zone_manifest_unified(no_flags)

        bad_flag_val = copy.deepcopy(zm)
        bad_flag_val["zones"][0]["protection_flags"]["protect_axioms"] = 1
        bad_flag_val["manifest_id"] = wca.compute_zone_manifest_id_clean(bad_flag_val)
        with self.assertRaisesRegex(ValueError, "must be bool"):
            wca.verify_zone_manifest_unified(bad_flag_val)

        no_scales = copy.deepcopy(zm)
        no_scales["zones"][0]["default_l2_scales"] = "bad"
        no_scales["manifest_id"] = wca.compute_zone_manifest_id_clean(no_scales)
        with self.assertRaisesRegex(ValueError, "default_l2_scales"):
            wca.verify_zone_manifest_unified(no_scales)

        bad_dom = copy.deepcopy(zm)
        bad_dom["zones"][0]["default_l2_scales"]["unknown_dom"] = "1"
        bad_dom["manifest_id"] = wca.compute_zone_manifest_id_clean(bad_dom)
        with self.assertRaisesRegex(ValueError, "unknown domain"):
            wca.verify_zone_manifest_unified(bad_dom)

        undef_prec = copy.deepcopy(zm)
        undef_prec["precedence_order"].append("html_report")
        undef_prec["manifest_id"] = wca.compute_zone_manifest_id_clean(undef_prec)
        with self.assertRaisesRegex(ValueError, "undefined zone"):
            wca.verify_zone_manifest_unified(undef_prec)

        extra_z = copy.deepcopy(zm)
        extra_z["precedence_order"] = ["formal_proof", "condensed_json", "ui_module", "code"]
        extra_z["manifest_id"] = wca.compute_zone_manifest_id_clean(extra_z)
        with self.assertRaisesRegex(ValueError, "omitted from precedence_order"):
            wca.verify_zone_manifest_unified(extra_z)

    def test_04_strict_weft_binding_guards(self) -> None:
        wm, wc = wca._make_sample_weft_pair()

        with self.assertRaisesRegex(ValueError, "mappings"):
            wca.verify_weft_binding_strict("bad", wc)  # type: ignore[arg-type]
        smuggled = copy.deepcopy(wm)
        smuggled["nested"] = [{"canaries": []}]
        with self.assertRaisesRegex(ValueError, "Forbidden inline canary"):
            wca.verify_weft_binding_strict(smuggled, wc)
        with self.assertRaisesRegex(ValueError, "schema"):
            wca.verify_weft_binding_strict(dict(wm, schema="bad"), wc)
        with self.assertRaisesRegex(ValueError, "adapter_class"):
            wca.verify_weft_binding_strict(dict(wm, adapter_class="class9"), wc)
        with self.assertRaisesRegex(ValueError, "derivation_recipe"):
            wca.verify_weft_binding_strict(dict(wm, derivation_recipe={}), wc)
        with self.assertRaisesRegex(ValueError, "plane1_hashes"):
            wca.verify_weft_binding_strict(dict(wm, plane1_hashes={}), wc)
        with self.assertRaisesRegex(ValueError, "Invalid plane1_hashes entry"):
            wca.verify_weft_binding_strict(dict(wm, plane1_hashes={"doc.md": "not-sha"}), wc)
        with self.assertRaisesRegex(ValueError, "layout_sha256"):
            wca.verify_weft_binding_strict(dict(wm, layout_sha256="bad"), wc)
        with self.assertRaisesRegex(ValueError, "checkpoint_fingerprint"):
            wca.verify_weft_binding_strict(dict(wm, checkpoint_fingerprint="bad"), wc)
        with self.assertRaisesRegex(ValueError, "config_hashes"):
            wca.verify_weft_binding_strict(dict(wm, config_hashes={}), wc)
        with self.assertRaisesRegex(ValueError, r"config_hashes\["):
            wca.verify_weft_binding_strict(dict(wm, config_hashes={"config.json": "bad"}), wc)
        with self.assertRaisesRegex(ValueError, r"tokenizer_hashes\["):
            wca.verify_weft_binding_strict(dict(wm, tokenizer_hashes={"tokenizer.json": "bad"}), wc)

        no_rflags = dict(wm)
        del no_rflags["runtime_flags_sha256"]
        with self.assertRaisesRegex(ValueError, "both runtime_flags"):
            wca.verify_weft_binding_strict(no_rflags, wc)
        bad_rflags = copy.deepcopy(wm)
        bad_rflags["runtime_flags"]["ctx_size"] = 8192
        with self.assertRaisesRegex(ValueError, "does not match runtime_flags_sha256"):
            wca.verify_weft_binding_strict(bad_rflags, wc)
        with self.assertRaisesRegex(ValueError, "ctx_size drift"):
            wca.verify_weft_binding_strict(wm, wc, expected_ctx_size=4096)

        with self.assertRaisesRegex(ValueError, "Impossible norm order"):
            wca.verify_weft_binding_strict(wm, dict(wc, frobenius_sq_scaled=10, spectral_norm_sq_scaled=11))
        with self.assertRaisesRegex(ValueError, "factor_digest in weft_certificate"):
            wca.verify_weft_binding_strict(wm, dict(wc, factor_digest="bad"))
        with self.assertRaisesRegex(ValueError, "quant_dtype"):
            wca.verify_weft_binding_strict(wm, dict(wc, quant_dtype=""))
        with self.assertRaisesRegex(ValueError, "factor_digest mismatch"):
            wca.verify_weft_binding_strict(dict(wm, factor_digest="b" * 64), wc)
        with self.assertRaisesRegex(ValueError, "certificate_sha256 mismatch"):
            wca.verify_weft_binding_strict(dict(wm, certificate_sha256="c" * 64), wc)

        with self.assertRaisesRegex(TypeError, "exact booleans"):
            wca.verify_weft_binding_strict(wm, wc, has_ssm_recurrent=1)  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "must be positive"):
            wca.verify_weft_binding_strict(wm, wc, has_horizontal_lattice=True, lattice_layers=0)
        with self.assertRaisesRegex(ValueError, "must be 0"):
            wca.verify_weft_binding_strict(wm, wc, has_horizontal_lattice=False, lattice_layers=4)

        # Boundary checks: exact equal spectral == frobenius and class2_open_recipe_base pass
        wc_eq = dict(wc, spectral_norm_sq_scaled=wc["frobenius_sq_scaled"])
        wm_c2 = dict(wm, adapter_class=wca.WEFT_CLASS_2, derivation_recipe=None, plane1_hashes={}, certificate_sha256=wca.canonical_sha256_ascii(wc_eq))
        res_c2 = wca.verify_weft_binding_strict(wm_c2, wc_eq)
        self.assertEqual(res_c2["adapter_class"], wca.WEFT_CLASS_2)

    def test_05_multibank_ledger_and_blueprint_guards(self) -> None:
        # Multi-bank flush guards (WD-X01)
        with self.assertRaisesRegex(ValueError, "non-empty"):
            wca.verify_multibank_flush_receipt_strict((), {}, {})
        with self.assertRaisesRegex(ValueError, "Unknown required"):
            wca.verify_multibank_flush_receipt_strict(("kv_cache", "mystery_bank"), {}, {})
        with self.assertRaisesRegex(ValueError, "kv_cache must always"):
            wca.verify_multibank_flush_receipt_strict(("ssm_recurrent",), {}, {})
        with self.assertRaisesRegex(ValueError, "must be mappings"):
            wca.verify_multibank_flush_receipt_strict(("kv_cache",), "bad", {})  # type: ignore[arg-type]
        with self.assertRaisesRegex(ValueError, "unconfirmed"):
            wca.verify_multibank_flush_receipt_strict(("kv_cache", "ssm_recurrent"), {}, {})

        kv_ok = wca.verify_multibank_flush_receipt_strict(("kv_cache",), {}, {"n_decoded": 0, "n_prompt_tokens_cache": 0})
        self.assertEqual(kv_ok["banks_confirmed"], ["kv_cache"])

        with self.assertRaisesRegex(ValueError, "residual taint"):
            wca.verify_multibank_flush_receipt_strict(("kv_cache",), {}, {"recurrent_state_tainted": True})
        with self.assertRaisesRegex(ValueError, "active_lora_ids"):
            wca.verify_multibank_flush_receipt_strict(("kv_cache",), {}, {"active_lora_ids": [0]})
        with self.assertRaisesRegex(ValueError, "cached tokens"):
            wca.verify_multibank_flush_receipt_strict(("kv_cache",), {}, {"n_decoded": 1, "n_prompt_tokens_cache": 0})
        with self.assertRaisesRegex(ValueError, "missing state_banks"):
            wca.verify_multibank_flush_receipt_strict(("kv_cache", "ssm_recurrent"), {"banks_flushed": ["kv_cache", "ssm_recurrent"]}, {})
        with self.assertRaisesRegex(ValueError, "missing explicit state_banks"):
            wca.verify_multibank_flush_receipt_strict(
                ("kv_cache", "ssm_recurrent"),
                {"banks_flushed": ["kv_cache", "ssm_recurrent"]},
                {"state_banks": {"kv_cache": {"tainted": False, "active_lora_ids": [], "tokens_or_layers": 0}}},
            )
        with self.assertRaisesRegex(ValueError, "is tainted"):
            wca.verify_multibank_flush_receipt_strict(
                ("kv_cache", "ssm_recurrent"),
                {"banks_flushed": ["kv_cache", "ssm_recurrent"]},
                {"state_banks": {"kv_cache": {"tainted": False, "active_lora_ids": [], "tokens_or_layers": 0}, "ssm_recurrent": {"tainted": True}}},
            )
        with self.assertRaisesRegex(ValueError, "retains active_lora_ids"):
            wca.verify_multibank_flush_receipt_strict(
                ("kv_cache", "ssm_recurrent"),
                {"banks_flushed": ["kv_cache", "ssm_recurrent"]},
                {"state_banks": {"kv_cache": {"tainted": False, "active_lora_ids": [], "tokens_or_layers": 0}, "ssm_recurrent": {"tainted": False, "active_lora_ids": [0], "tokens_or_layers": 0}}},
            )
        with self.assertRaisesRegex(ValueError, "non-zero tokens_or_layers"):
            wca.verify_multibank_flush_receipt_strict(
                ("kv_cache", "ssm_recurrent"),
                {"banks_flushed": ["kv_cache", "ssm_recurrent"]},
                {"state_banks": {"kv_cache": {"tainted": False, "active_lora_ids": [], "tokens_or_layers": 0}, "ssm_recurrent": {"tainted": False, "active_lora_ids": [], "tokens_or_layers": 3}}},
            )

        # Ledger guards (WD-X05)
        key = b"test-secret-key-16bytes-minimum!"
        body = {
            "seq": 1, "timestamp_utc": "2026-11-21T00:00:00Z", "event": "mount",
            "prev_receipt_sha256": wca.GENESIS_HASH, "checkpoint_fingerprint_sha256": "1" * 64,
            "runtime_flags_sha256": "2" * 64, "slot_manifest_digest": "3" * 64,
            "adapters": [], "stage_failed": None, "error_code": None, "reason": "ok",
            "slots_flushed": [0], "details": {},
        }
        r_sha = wca.canonical_sha256_ascii(body)
        sig = hmac.new(key, f"{r_sha}:hmac-sha256:k1".encode("ascii"), hashlib.sha256).hexdigest()
        rec = dict(body, receipt_sha256=r_sha, sig_alg="hmac-sha256", key_id="k1", signature=sig)
        line = json.dumps(rec, sort_keys=True, separators=(",", ":"))

        with self.assertRaisesRegex(ValueError, "length >= 16"):
            wca.verify_signed_ledger_line_strict(line, expected_seq=1, expected_prev_sha256=wca.GENESIS_HASH, secret_key=b"short", expected_key_id="k1")
        with self.assertRaisesRegex(ValueError, "JSON object"):
            wca.verify_signed_ledger_line_strict("[]", expected_seq=1, expected_prev_sha256=wca.GENESIS_HASH, secret_key=key, expected_key_id="k1")
        with self.assertRaisesRegex(ValueError, "key mismatch"):
            wca.verify_signed_ledger_line_strict('{"seq":1}', expected_seq=1, expected_prev_sha256=wca.GENESIS_HASH, secret_key=key, expected_key_id="k1")
        with self.assertRaisesRegex(ValueError, "sequence mismatch"):
            wca.verify_signed_ledger_line_strict(line, expected_seq=2, expected_prev_sha256=wca.GENESIS_HASH, secret_key=key, expected_key_id="k1")
        bad_ev = json.dumps(dict(rec, event="forged"))
        with self.assertRaisesRegex(ValueError, "Unsupported ledger event"):
            wca.verify_signed_ledger_line_strict(bad_ev, expected_seq=1, expected_prev_sha256=wca.GENESIS_HASH, secret_key=key, expected_key_id="k1")
        bad_slots = json.dumps(dict(rec, slots_flushed=[True]))
        with self.assertRaisesRegex(ValueError, "slots_flushed"):
            wca.verify_signed_ledger_line_strict(bad_slots, expected_seq=1, expected_prev_sha256=wca.GENESIS_HASH, secret_key=key, expected_key_id="k1")
        with self.assertRaisesRegex(ValueError, "chain mismatch"):
            wca.verify_signed_ledger_line_strict(line, expected_seq=1, expected_prev_sha256="f" * 64, secret_key=key, expected_key_id="k1")
        bad_body = json.dumps(dict(rec, reason="tampered"))
        with self.assertRaisesRegex(ValueError, "body tamper"):
            wca.verify_signed_ledger_line_strict(bad_body, expected_seq=1, expected_prev_sha256=wca.GENESIS_HASH, secret_key=key, expected_key_id="k1")
        with self.assertRaisesRegex(ValueError, "key_id mismatch"):
            wca.verify_signed_ledger_line_strict(line, expected_seq=1, expected_prev_sha256=wca.GENESIS_HASH, secret_key=key, expected_key_id="other")
        bad_sig = json.dumps(dict(rec, signature="0" * 64))
        with self.assertRaisesRegex(ValueError, "HMAC signature mismatch"):
            wca.verify_signed_ledger_line_strict(bad_sig, expected_seq=1, expected_prev_sha256=wca.GENESIS_HASH, secret_key=key, expected_key_id="k1")

        # Secret redaction list + non-str branch
        self.assertEqual(wca.redact_ledger_secrets([123, "api_key=supersecret999"]), [123, "api_key=[REDACTED]"])

        # Blueprint empty-string guard + positive/negative static detection checks
        with self.assertRaisesRegex(ValueError, "non-empty strings"):
            wca.audit_blueprint_static_invariants(
                mkosi_conf_text="", postinst_text="x", harden_text="x",
                modeld_service_text="x", llama_service_text="x", recovery_text="x", architecture_text="x",
            )
        bp_clean = wca.audit_blueprint_static_invariants(
            mkosi_conf_text="rootflags=subvol=@\nmkosi.extra\n",
            postinst_text="chown root:warp-modeld /etc/warp/keys\nchown warp-modeld:warp-modeld /var/lib/warp-ledger\n",
            harden_text="for ancestor in \\\n  /etc/warp \\\nfor tree in /etc/warp/canaries",
            modeld_service_text="User=warp-modeld\nGroup=warp-rpc\nSupplementaryGroups=warp-modeld\nStateDirectory=warp-ledger\n",
            llama_service_text="--lora-init-without-apply",
            recovery_text='ukify build && bootctl set-oneshot "warp-rollback-${ckpt_id}.efi"',
            architecture_text="Subvolume `@snapshots` persists across rollbacks.",
        )
        self.assertFalse(bp_clean["wd_x06_uki_subvol_disconnect"])
        self.assertTrue(bp_clean["wd_x06_snapshots_subvol_declared_in_arch"])
        self.assertFalse(bp_clean["wd_x07a_etc_warp_missing_from_harden_ancestors"])
        self.assertFalse(bp_clean["wd_x07b_statedir_and_keys_group_collision"])
        self.assertTrue(bp_clean["wd_x07c_binaries_installed_by_mkosi"])

    def test_06_live_ecosystem_assertions(self) -> None:
        if "live_ecosystem_audit" in self.cert_live:
            la = self.cert_live["live_ecosystem_audit"]
            self.assertEqual(la["repos_inspected_read_only"], 10)
            self.assertTrue(la["warp_drive_equals_siliconcordat_warp_zero_diff"])
            self.assertEqual(la["warp_drive_file_count"], 45)
            self.assertEqual(
                la["real_mde_zone_manifest_verified"]["manifest_id"],
                "sha256:4e00656cb47fce97f687ae638afba22c569b9680b3780eeb2e5ea71a62c55eca",
            )
            self.assertTrue(la["issue2_weft_disambiguation"]["siliconcordat_weft_has_compiler"])
            self.assertFalse(la["issue2_weft_disambiguation"]["moissanite_weft_has_compiler_at_src_weft"])
            self.assertTrue(la["blueprint_static_audit"]["wd_x06_uki_subvol_disconnect"])
            self.assertTrue(la["blueprint_static_audit"]["wd_x07a_etc_warp_missing_from_harden_ancestors"])
            self.assertTrue(la["blueprint_static_audit"]["wd_x07b_statedir_and_keys_group_collision"])


if __name__ == "__main__":
    unittest.main()
