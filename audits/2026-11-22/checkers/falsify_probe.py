#!/usr/bin/env python3
# Audit checker copy, 2026-11-22. Run from the repo root, for example: python3 -I -B audits/2026-11-22/checkers/<name>.py
# The repo root is derived from this file location. No edit is needed.
import hashlib, inspect, json, math, sys, tempfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
out = []
def say(k, v):
    out.append(f"{k}={v}")

# F1 cert self-attestation
from warp_modeld.certificate import FixedRadixCertificate, CertificateBounds, RationalBound, verify_division_free
bounds = CertificateBounds(max_frobenius_sq=RationalBound(5,1), max_spectral_norm_sq=RationalBound(2,1), max_leakage_energy=RationalBound(1,100), max_safety_dot_sq=RationalBound(1,1000))
cert = FixedRadixCertificate.create(adapter_id="evil", adapter_sha256="a"*64, base_weights_sha256="b"*64, radix_scale=1<<20, frobenius_sq_scaled=1, spectral_norm_sq_scaled=1, leakage_energy_scaled=0, max_safety_dot_sq_scaled=0)
try:
    r = verify_division_free(cert, bounds)
    say("F1_invented_passes", r.passed)
except Exception as e:
    say("F1_invented_passes", f"raise:{type(e).__name__}")
try:
    FixedRadixCertificate.create(adapter_id="x", adapter_sha256="a"*64, base_weights_sha256="b"*64, radix_scale=1<<20, frobenius_sq_scaled=True, spectral_norm_sq_scaled=0, leakage_energy_scaled=0, max_safety_dot_sq_scaled=0)
    say("F1_bool_rejected", False)
except Exception:
    say("F1_bool_rejected", True)

# F2 fingerprint conditional
import helpers as H
from warp_modeld.fingerprint import AdapterBundle, verify_stage1
bd = H.make_adapter_bundle_dict(adapter_path=None)
bundle = AdapterBundle.from_dict(bd)
rep = verify_stage1(bundle, H.make_checkpoint(), H.make_lineage(), H.make_runtime_flags())
say("F2_none_path_verified_flag", rep.adapter_file_verified)
from warp_modeld.verifier import WarpModeld
say("F2_lib_default_require_files", inspect.signature(WarpModeld.__init__).parameters["require_loaded_adapter_files"].default)
cli_src = (ROOT/"src/warp_modeld/cli.py").read_text()
say("F2_cli_default_true", 'cfg.get("require_loaded_adapter_files", True)' in cli_src)

# F3 NaN ACCEPT
from warp_modeld.experiment import Measurements, apply_acceptance_policy, load_contract
contract = load_contract(ROOT/"experiments/demo-2026-11-22")
nan = float("nan")
m = Measurements(task_top1=nan, task_contested_fix_fraction=nan, task_break_fraction=nan, margin_threshold=-0.37, margins_adapter=(-0.10,0.0,0.18)*28, margins_baseline=(-1.0,-0.9,-0.81)*12, margin_adapter_requests=84, margin_baseline_requests=36, iid_mean_kl=nan, iid_top1_agreement=nan, shifted_mean_kl=nan, safety_canaries_run=9, safety_failures=(), rollback_exact_matches=14, rollback_sequences=14, rollback_max_logit_diff=0.0)
v = apply_acceptance_policy(m, contract.thresholds, expected_canaries=9)
say("F3_nan_verdict", v.verdict)
say("F3_nan_failed", list(v.failed_gates))

# F4 ReceiptLog
from warp_modeld.experiment import ReceiptLog
with tempfile.TemporaryDirectory() as td:
    p = Path(td)/"r.jsonl"
    log = ReceiptLog(p)
    log.append("e1", x=1); log.append("e2", x=2)
    lines = p.read_text().splitlines()
    e = json.loads(lines[0]); e["x"] = 999
    lines[0] = json.dumps(e, sort_keys=True)
    p.write_text("\n".join(lines)+"\n")
    say("F4_tampered_verify_chain", log.verify_chain())
    try:
        log.append("e3", x=3)
        say("F4_append_after_tamper", "ok")
    except Exception as ex:
        say("F4_append_after_tamper", f"raise:{type(ex).__name__}")
    say("F4_after_verify_chain", log.verify_chain())

# F5 slot clean default
from warp_modeld.canary import _is_slot_clean_for_banks
class NoSlots: pass
say("F5_no_list_slots_clean", _is_slot_clean_for_banks(NoSlots(), 0, ("kv_cache",)))

# F6 llama parser
from warp_modeld.llama_client import LlamaServerClient
c = object.__new__(LlamaServerClient)
c._request = lambda method, path, payload=None: [{"id": True, "path": "/x.gguf", "scale": float("nan")}]
ads = c.list_lora_adapters()
say("F6_bool_id", ads[0].id)
say("F6_nan_scale_isfinite", math.isfinite(ads[0].scale))
say("F6_nan_abs_gt0", abs(ads[0].scale) > 0.0)

# F7 mount before digest: dynamic with own fakes
from warp_modeld.experiment import ExperimentController, CompileResult
order = []
class FC:
    def compile(self, cand, parent):
        return CompileResult(adapter_sha256="c"*64, command="x", command_version="v", timing_ms=1.0, compiler_repo=contract.compiler_repo, compiler_commit=contract.compiler_commit)
class FR:
    def mount_adapter(self, sha, scale):
        order.append("mount")
        return 1.0
class FL: pass
with tempfile.TemporaryDirectory() as td:
    rp = Path(td)/"r.jsonl"
    orig_append = ReceiptLog.append
    def spy(self, event, **kw):
        order.append(f"log:{event}")
        return orig_append(self, event, **kw)
    ReceiptLog.append = spy
    try:
        ctl = ExperimentController(contract=contract, compiler=FC(), runtime=FR(), lifecycle=FL(), receipts=ReceiptLog(rp), environment={})
        cand = ctl.propose({"eta": 0.01, "lora_scale": 1.0})
        ctl.compile_and_bind(cand, actual_parent_sha256=contract.parent_sha256)
    finally:
        ReceiptLog.append = orig_append
say("F7_order", order)

# F8 kill switch not inference gate (source inspection of bodies)
src_i = inspect.getsource(WarpModeld.infer); src_c = inspect.getsource(WarpModeld.complete); src_m = inspect.getsource(WarpModeld.mount_stack)
say("F8_infer_has_kill", "_kill_switch_engaged" in src_i)
say("F8_complete_has_kill", "_kill_switch_engaged" in src_c)
say("F8_mount_has_kill", "_kill_switch_engaged" in src_m)

# F9 SignedLedger fork
from warp_modeld.ledger import SignedLedger, HmacSha256Signer, LedgerVerifier
with tempfile.TemporaryDirectory() as td:
    lp = Path(td)/"l.jsonl"
    signer = HmacSha256Signer(b"k"*32, key_id="t1")
    led = SignedLedger(lp, signer)
    led.append("mount", checkpoint_fingerprint_sha256="a"*64, runtime_flags_sha256="b"*64, slot_manifest_digest=None)
    txt = lp.read_text()
    lp.write_text(txt.replace("mount", "mount"))
    # tamper reason field value while keeping JSON valid
    d = json.loads(txt.strip()); d["reason"] = "tampered"
    lp.write_text(json.dumps(d, sort_keys=True, separators=(",",":"))+"\n")
    try:
        led.append("mount", checkpoint_fingerprint_sha256="a"*64, runtime_flags_sha256="b"*64, slot_manifest_digest=None)
        say("F9_append_after_tamper", "ok")
    except Exception as ex:
        say("F9_append_after_tamper", f"raise:{type(ex).__name__}")
    try:
        LedgerVerifier.verify_file(lp, signer)
        say("F9_verify_after", "ok")
    except Exception as ex:
        say("F9_verify_after", f"raise:{type(ex).__name__}")

# F10 cerebras NaN constraint
from warp_modeld.cerebras_client import validate_propose_context
try:
    cleaned = validate_propose_context({"constraints": {"max": float("nan")}})
    say("F10_nan_constraint_accepted", math.isnan(cleaned["constraints"]["max"]))
    say("F10_dumps_bare_nan", "NaN" in json.dumps(cleaned))
except Exception as ex:
    say("F10_nan_constraint_accepted", f"raise:{type(ex).__name__}")
try:
    validate_propose_context({"baseline_metrics": {"a": float("nan")}})
    say("F10_nan_metric_rejected", False)
except Exception:
    say("F10_nan_metric_rejected", True)

# Schema defect (Lane B)
s = json.loads((ROOT/"experiments/demo-2026-11-22/receipt.schema.json").read_text())
say("SCHEMA_version_type", type(s["properties"]["receipt_schema_version"]).__name__)
try:
    import jsonschema
    jsonschema.validators.validator_for(s).check_schema(s)
    say("SCHEMA_check", "ok")
except Exception as ex:
    say("SCHEMA_check", f"raise:{type(ex).__name__}")
s2 = json.loads(json.dumps(s)); s2["properties"]["receipt_schema_version"] = {"const": "0.1.0"}
try:
    import jsonschema
    jsonschema.validators.validator_for(s2).check_schema(s2)
    say("SCHEMA_steelman_check", "ok")
except Exception as ex:
    say("SCHEMA_steelman_check", f"raise:{type(ex).__name__}")

# Headline cert + manifest (Lane B/D)
certd = json.loads((ROOT/"studies/expedition-bounded-controller/bounded_controller_certificate.json").read_text())
body = {k: v for k, v in certd.items() if k != "canonical_sha256"}
mine = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
say("CERT_bounded_match", mine == certd["canonical_sha256"])
say("CERT_bounded_sha12", mine[:12])
man = json.loads((ROOT/"experiments/demo-2026-11-22/manifest.json").read_text())
expdir = ROOT/"experiments/demo-2026-11-22"
task_bytes = (expdir/"suites/task.json").read_bytes()
say("MAN_task_match", hashlib.sha256(task_bytes).hexdigest() == man["digests"]["task"])
comb = b"".join((expdir/f"suites/{n}").read_bytes() for n in ["task.json","retention_iid.json","retention_shifted.json","safety_canaries.json"])
say("MAN_combined_match", hashlib.sha256(comb).hexdigest() == man["digests"]["combined_suites"])
say("MAN_file_sha_match", hashlib.sha256((expdir/"manifest.json").read_bytes()).hexdigest() == (expdir/"manifest.sha256").read_text().strip())
for name, f, key in [("task","suites/task.json","cases"),("iid","suites/retention_iid.json","cases"),("shifted","suites/retention_shifted.json","cases")]:
    d = json.loads((expdir/f).read_text()); say(f"COUNT_{name}", len(d[key]))
say("COUNT_modules", len(list((ROOT/"src/warp_modeld").glob("*.py"))))
say("COUNT_lines", sum(len(p.read_text().splitlines()) for p in (ROOT/"src/warp_modeld").glob("*.py")))
lk = json.loads((expdir/"audit/split_leakage.json").read_text())
say("LEAK_reusing", lk.get("reusing_train_pair")); say("LEAK_held", lk.get("held_out_states"))
print("\n".join(out))
