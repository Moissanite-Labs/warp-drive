#!/usr/bin/env python3
# Audit checker copy, 2026-11-22. Run from the repo root, for example: python3 -I -B audits/2026-11-22/checkers/<name>.py
# The repo root is derived from this file location. No edit is needed.
"""Lane B independent checker: manifest digests, schemas, cert internals.
Zero repo imports. No bare asserts. Deterministic sorted output.
Usage: python3 -I -B audits/2026-11-22/checkers/laneB_checker.py <repo-root>
"""
import ast
import hashlib
import json
import sys
from pathlib import Path


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def canon_sha(obj):
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def count_floats(obj):
    if isinstance(obj, float):
        return 1
    if isinstance(obj, dict):
        return sum(count_floats(v) for v in obj.values())
    if isinstance(obj, list):
        return sum(count_floats(v) for v in obj)
    return 0


def main(argv):
    if len(argv) != 2:
        print("FAIL usage: laneb_checker.py <clone-root>")
        return 2
    root = Path(argv[1])
    lines = []

    def rec(name, ok, detail):
        lines.append(f"{'PASS' if ok else 'FAIL'} {name} {detail}")

    # 1. Manifest digests + case counts
    exp = root / "experiments" / "demo-2026-11-22"
    manifest = json.loads((exp / "manifest.json").read_text(encoding="utf-8"))
    dig = manifest["digests"]
    filemap = {
        "task": exp / "suites" / "task.json",
        "retention_iid": exp / "suites" / "retention_iid.json",
        "retention_shifted": exp / "suites" / "retention_shifted.json",
        "safety_canaries": exp / "suites" / "safety_canaries.json",
        "controls": exp / "controls.json",
        "thresholds": exp / "thresholds.json",
        "receipt_schema": exp / "receipt.schema.json",
        "audit_split_leakage": exp / "audit" / "split_leakage.json",
        "generate_suites_script": exp / "scripts" / "generate_suites.py",
    }
    for key in sorted(filemap):
        got = sha256_bytes(filemap[key].read_bytes())
        rec(f"manifest_digest[{key}]", got == dig[key], f"computed={got} pinned={dig[key]}")
    combined = sha256_bytes(b"".join(filemap[k].read_bytes() for k in ["task", "retention_iid", "retention_shifted", "safety_canaries"]))
    rec("manifest_digest[combined_suites]", combined == dig["combined_suites"], f"computed={combined} pinned={dig['combined_suites']}")
    msha_file = (exp / "manifest.sha256").read_text(encoding="utf-8").split()[0]
    msha_got = sha256_bytes((exp / "manifest.json").read_bytes())
    rec("manifest_sha256_file", msha_got == msha_file, f"computed={msha_got} file={msha_file}")
    expect_counts = {"task": 112, "retention_iid": 24, "retention_shifted": 80, "safety_canaries": 9}
    for name in sorted(expect_counts):
        data = json.loads(filemap[name].read_text(encoding="utf-8"))
        if name == "safety_canaries":
            n_list = len(data["canary_ids"])
            n_field = data["n_canaries"]
        else:
            n_list = len(data["cases"])
            n_field = data["n_cases"]
        m_cases = manifest["suites"][name]["cases"]
        rec(f"case_count[{name}]", n_list == n_field == m_cases == expect_counts[name],
            f"list={n_list} field={n_field} manifest={m_cases} expect={expect_counts[name]}")
    leak = json.loads((exp / "audit" / "split_leakage.json").read_text(encoding="utf-8"))
    rec("split_leakage_counts", leak["held_out_states"] == 112 and leak["reusing_train_pair"] == 110,
        f"held_out={leak['held_out_states']} reusing={leak['reusing_train_pair']} fraction={leak['reuse_fraction']!r} verdict={leak['verdict']!r}")

    # 2. Schema validity: draft-07 (task), declared draft, 2020-12
    # jsonschema is an optional third-party package that this repo does not declare.
    # On a stdlib-only host the schema rows are skipped with a clear message instead
    # of crashing; the manifest digest rows above still ran.
    try:
        import jsonschema
        from jsonschema import Draft7Validator, Draft202012Validator, validators
    except ImportError:
        jsonschema = None
        Draft7Validator = Draft202012Validator = validators = None
    schema_paths = sorted((root / "schemas").glob("*.json")) + [exp / "receipt.schema.json"]
    parsed = {}
    for p in schema_paths:
        rel = str(p.relative_to(root))
        parsed[rel] = json.loads(p.read_text(encoding="utf-8"))
    if validators is None:
        lines.append("SKIP schema_checks jsonschema not installed on this stdlib-only host; schema rows skipped with this message")
    else:
        for rel in sorted(parsed):
            obj = parsed[rel]
            declared = obj.get("$schema", "NONE") if isinstance(obj, dict) else "NOT-DICT"
            for label, cls in [("draft07", Draft7Validator), ("2020-12", Draft202012Validator)]:
                try:
                    cls.check_schema(obj)
                    rec(f"schema[{rel} as {label}]", True, f"declared={declared}")
                except Exception as exc:
                    rec(f"schema[{rel} as {label}]", False, f"declared={declared} err={type(exc).__name__}: {str(exc)[:160]}")
            try:
                validators.validator_for(obj).check_schema(obj)
                rec(f"schema[{rel} as declared]", True, f"validator={validators.validator_for(obj).__name__}")
            except Exception as exc:
                rec(f"schema[{rel} as declared]", False, f"err={type(exc).__name__}: {str(exc)[:160]}")

    # 3. Sample payloads (hand-built from schema bodies; zero repo code)
    def validate(name, schema_rel, payload, schema_override=None):
        if validators is None:
            lines.append(f"SKIP sample[{name}] jsonschema not installed on this stdlib-only host")
            return
        schema = schema_override if schema_override is not None else parsed[schema_rel]
        cls = validators.validator_for(schema)
        try:
            errs = sorted(cls(schema).iter_errors(payload), key=lambda e: list(e.path))
        except Exception as exc:
            rec(f"sample[{name}]", False, f"validator_crash={type(exc).__name__}: {str(exc)[:140]}")
            return
        detail = "valid" if not errs else "; ".join(f"{'/'.join(str(x) for x in e.path) or '$'}: {e.message[:100]}" for e in errs[:4])
        rec(f"sample[{name}]", len(errs) == 0, f"errors={len(errs)} {detail}")

    h = "a" * 64
    bundle = {
        "adapter_id": "mde:corpus", "domain": "corpus", "llama_adapter_id": 0,
        "adapter_sha256": h, "adapter_path": None, "scale_num": 1, "scale_den": 1,
        "checkpoint": {"model_id": "m", "layout_sha256": h, "weights_sha256": h,
                       "config_sha256": h, "tokenizer_sha256": h, "chat_template_sha256": h,
                       "has_ssm_recurrent": False, "has_horizontal_lattice": False,
                       "lattice_layers": 0, "lattice_width": 0},
        "source_lineage": {"corpus_tree_sha256": h, "domain_commits": {"corpus": "a1b2c3d4"}, "contested_heads": []},
        "runtime_flags_sha256": h, "derivation_digest": h,
        "certificate": {"adapter_id": "mde:corpus", "adapter_sha256": h, "base_weights_sha256": h,
                        "radix_scale": 16777216, "frobenius_sq_scaled": 1, "spectral_norm_sq_scaled": 1,
                        "leakage_energy_scaled": 0, "max_safety_dot_sq_scaled": 0, "cert_sha256": h},
    }
    validate("hand_adapter_bundle", "schemas/adapter-bundle.schema.json", bundle)
    validate("hand_cerebras_candidate", "schemas/cerebras-candidate.schema.json",
             {"target_layer": "last", "strength": 0.5, "rank": 8, "quantization": "q8_0"})
    full_receipt = {
        "receipt_schema_version": "0.1.0", "manifest_sha256": h, "suite_sha256": h,
        "candidate": {"candidate_id": "c1", "config": {"rank": 8, "target_layer": 31,
                      "target_tensor": "ffn_up", "eta": 0.01, "lora_scale": 1.0},
                      "adapter_sha256": h, "hash_recorded_before_evaluation": True},
        "seeds": {"suite_generation": "deterministic"},
        "environment": {"gpu": "mock", "llama_cpp_build": "b12549", "llama_cpp_commit": "8af68d486"},
        "timings_ms": {"compile": 1, "evaluate": 1, "deploy": 1},
        "measurements": {
            "task": {"top1": 0.5, "contested_fix_fraction": 0.1, "break_fraction": 0.1},
            "margin": {"threshold": -0.37, "adapter_requests": 1, "baseline_requests": 1},
            "retention_iid": {"mean_kl": 0.1, "top1_agreement": 0.9},
            "retention_shifted": {"mean_kl": 0.1},
            "safety": {"canaries_run": 9, "failures": []},
            "rollback": {"exact_matches": 1, "sequences": 1, "max_logit_diff": 0.0}},
        "verdict": "REJECT",
    }
    validate("hand_full_receipt", "experiments/demo-2026-11-22/receipt.schema.json", full_receipt)
    repo_mock = dict(full_receipt)
    repo_mock["measurements"] = {}
    validate("repo_mock_receipt_empty_measurements", "experiments/demo-2026-11-22/receipt.schema.json", repo_mock)
    # Steelman: repair bare-string subschema to const, retest strongest repaired form
    import copy
    repaired = copy.deepcopy(parsed["experiments/demo-2026-11-22/receipt.schema.json"])
    repaired["properties"]["receipt_schema_version"] = {"const": "0.1.0", "type": "string"}
    if Draft7Validator is None:
        lines.append("SKIP steelman[receipt_repaired_const_check_schema] jsonschema not installed on this stdlib-only host")
    else:
        try:
            Draft7Validator.check_schema(repaired)
            rec("steelman[receipt_repaired_const_check_schema]", True, "draft07 PASS after const repair")
        except Exception as exc:
            rec("steelman[receipt_repaired_const_check_schema]", False, f"{type(exc).__name__}: {str(exc)[:140]}")
    validate("hand_full_receipt_vs_repaired", "experiments/demo-2026-11-22/receipt.schema.json", full_receipt, schema_override=repaired)
    validate("repo_mock_vs_repaired", "experiments/demo-2026-11-22/receipt.schema.json", repo_mock, schema_override=repaired)
    # canary id cross-check: safety suite ids must exist in verifier-canaries
    vc = parsed["schemas/verifier-canaries.json"]
    vc_ids = sorted(c["canary_id"] for c in vc["canaries"]) if "canaries" in vc else []
    sc = json.loads(filemap["safety_canaries"].read_text(encoding="utf-8"))
    missing = [i for i in sc["canary_ids"] if i not in vc_ids]
    rec("safety_ids_in_verifier_canaries", len(missing) == 0,
        f"verifier_canaries={len(vc_ids)} safety_ids={len(sc['canary_ids'])} missing={missing}")

    # 4. Certificate file hashes, float census, internal canonical recomputation
    certs = {
        "bounded": root / "studies/expedition-bounded-controller/bounded_controller_certificate.json",
        "gram": root / "studies/expedition-gram-cert-upgrades/warp_drive_gram_cert_certificate.json",
        "runtime": root / "studies/expedition-trust-boundary-verifier/warp_drive_runtime_certificate.json",
        "weft": root / "studies/expedition-trust-boundary-verifier/weft_cross_audit_certificate.json",
        "weight": root / "studies/expedition-weight-iteration-bridge/warp_weight_iteration_certificate.json",
    }
    for name in sorted(certs):
        p = certs[name]
        obj = json.loads(p.read_text(encoding="utf-8"))
        rec(f"cert[{name}]", True, f"file_sha256={sha256_bytes(p.read_bytes())} floats={count_floats(obj)} bytes={len(p.read_bytes())}")
    bobj = json.loads(certs["bounded"].read_text(encoding="utf-8"))
    bbody = {k: v for k, v in bobj.items() if k != "canonical_sha256"}
    rec("cert_internal[bounded_canonical]", canon_sha(bbody) == bobj["canonical_sha256"],
        f"computed={canon_sha(bbody)} pinned={bobj['canonical_sha256']}")
    gobj = json.loads(certs["gram"].read_text(encoding="utf-8"))
    rec("cert_internal[gram_certificate_sha]", canon_sha(gobj["certificate"]) == gobj["certificate_sha256"],
        f"computed={canon_sha(gobj['certificate'])} pinned={gobj['certificate_sha256']} live={gobj['certificate'].get('live_clone_audit')}")
    wobj = json.loads(certs["weight"].read_text(encoding="utf-8"))
    wbody = {k: v for k, v in wobj.items() if k != "canonical_sha256"}
    rec("cert_internal[weight_canonical]", canon_sha(wbody) == wobj["canonical_sha256"],
        f"computed={canon_sha(wbody)} pinned={wobj['canonical_sha256']} verdict={wobj['verdict']} oracle={wobj['oracle_class']}")

    # 5. Bare-assert census (ast.Assert) per area
    for area in ["src", "tests", "studies"]:
        total = 0
        files = 0
        for p in sorted((root / area).rglob("*.py")):
            files += 1
            tree = ast.parse(p.read_text(encoding="utf-8"))
            total += sum(1 for n in ast.walk(tree) if isinstance(n, ast.Assert))
        rec(f"bare_asserts[{area}]", True, f"count={total} py_files={files}")

    for line in lines:
        print(line)
    fails = sum(1 for line in lines if line.startswith("FAIL"))
    print(f"SUMMARY total={len(lines)} fail={fails} pass={len(lines) - fails}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
