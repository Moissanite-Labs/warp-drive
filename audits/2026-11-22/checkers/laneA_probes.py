#!/usr/bin/env python3
# Audit checker copy, 2026-11-22. Run from the repo root, for example: python3 -I -B audits/2026-11-22/checkers/<name>.py
# The repo root is derived from this file location. No edit is needed.
import sys, json, math, hashlib, tempfile
from pathlib import Path
import pathlib as _pl
_R = _pl.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_R / "src"))
out = []
def rec(name, verdict, detail):
    out.append(f"{name}: {verdict} :: {detail}")

# P1: forged self-signed certificate passes Stage 2; Stage1 passes with no adapter file
from warp_modeld.certificate import FixedRadixCertificate, CertificateBounds, RationalBound, verify_division_free
bounds = CertificateBounds(max_frobenius_sq=RationalBound(1,1), max_spectral_norm_sq=RationalBound(1,1),
    max_leakage_energy=RationalBound(1,1), max_safety_dot_sq=RationalBound(1,1))
fake_weights = "a"*64; fake_adapter = "b"*64
forged = FixedRadixCertificate.create(adapter_id="evil", adapter_sha256=fake_adapter,
    base_weights_sha256=fake_weights, radix_scale=1<<20,
    frobenius_sq_scaled=1, spectral_norm_sq_scaled=1, leakage_energy_scaled=0, max_safety_dot_sq_scaled=0)
try:
    r = verify_division_free(forged, bounds, expected_adapter_id="evil",
        expected_adapter_sha256=fake_adapter, expected_base_weights_sha256=fake_weights)
    rec("P1a_forged_cert", "FAIL-OPEN-CONFIRMED", f"self-hashed cert with invented metrics passed, passed={r.passed}")
except Exception as e:
    rec("P1a_forged_cert", "CLOSED", str(e)[:120])

# P1b: bool as int metric
try:
    FixedRadixCertificate.create(adapter_id="x", adapter_sha256=fake_adapter, base_weights_sha256=fake_weights,
        radix_scale=1024, frobenius_sq_scaled=True, spectral_norm_sq_scaled=0, leakage_energy_scaled=0, max_safety_dot_sq_scaled=0)
    rec("P1b_bool_metric", "FAIL-OPEN", "True accepted as frobenius")
except Exception as e:
    rec("P1b_bool_metric", "CLOSED", type(e).__name__ + ": " + str(e)[:80])

# P2: NaN measurements through public policy
from warp_modeld.experiment import Measurements, apply_acceptance_policy
thr = {"task": {"top1_min": 0.9, "contested_fix_min_fraction": 0.9, "break_max_fraction": 0.01},
       "adapter_application_margin": {"threshold": 0.5},
       "retention": {"iid_kl_max_mean": 0.001, "iid_top1_agreement_min": 0.99, "shifted_kl_max_mean": 0.001}}
nan = float("nan")
m = Measurements(task_top1=nan, task_contested_fix_fraction=nan, task_break_fraction=nan,
    margin_threshold=0.5, margins_adapter=(1.0,)*84, margins_baseline=(0.0,)*36,
    margin_adapter_requests=84, margin_baseline_requests=36,
    iid_mean_kl=nan, iid_top1_agreement=nan, shifted_mean_kl=nan,
    safety_canaries_run=4, safety_failures=(), rollback_exact_matches=14, rollback_sequences=14, rollback_max_logit_diff=0.0)
try:
    v = apply_acceptance_policy(m, thr, expected_canaries=4)
    rec("P2_nan_policy", "FAIL-OPEN-CONFIRMED" if v.verdict=="ACCEPT" else "CLOSED",
        f"verdict={v.verdict} failed={v.failed_gates} (6 NaN gates)")
except Exception as e:
    rec("P2_nan_policy", "CLOSED", f"raise:{type(e).__name__}: {str(e)[:100]}")

# P3: ReceiptLog append trusts tampered prev without verify
from warp_modeld.experiment import ReceiptLog
with tempfile.TemporaryDirectory() as td:
    p = Path(td)/"r.jsonl"; log = ReceiptLog(p)
    log.append("a", value=1); log.append("b", value=2)
    lines = p.read_text().splitlines(); e0 = json.loads(lines[0]); e0["value"] = 999
    lines[0] = json.dumps(e0, sort_keys=True); p.write_text("\n".join(lines)+"\n")
    chain_ok_before = log.verify_chain()
    try:
        log.append("c", value=3); appended = True
    except Exception:
        appended = False
    rec("P3_receiptlog_tamper_append", "FAIL-OPEN-CONFIRMED" if appended else "CLOSED",
        f"verify_chain_after_tamper={chain_ok_before} append_succeeded={appended} entries={len(log.read_all())}")

# P4: _is_slot_clean_for_banks default True when client lacks list_slots
from warp_modeld.canary import _is_slot_clean_for_banks
class NoSlots: pass
rec("P4_slot_clean_default", "FAIL-OPEN-CONFIRMED" if _is_slot_clean_for_banks(NoSlots(), 0, ("kv_cache","lattice_horizontal_streams")) else "CLOSED",
    "client without list_slots -> True")

# P5: NaN adapter scale evades abs(scale)>0 guard (pure predicate + parser)
from warp_modeld.llama_client import LlamaAdapterInfo
info = LlamaAdapterInfo(id=7, path="/x.gguf", scale=float("nan"))
evades = not (abs(info.scale) > 0.0)
rec("P5_nan_scale", "FAIL-OPEN-CONFIRMED" if evades else "CLOSED",
    f"abs(nan)>0.0 is False; canary.py:519/773 guard and verifier rely on this; list_lora_adapters float() has no isfinite (str 'nan' parses)")

# P6: SignedLedger append after external tamper (in-memory head trusted)
from warp_modeld.ledger import SignedLedger, HmacSha256Signer, LedgerVerifier
with tempfile.TemporaryDirectory() as td:
    p = Path(td)/"l.jsonl"; s = HmacSha256Signer(b"k"*32)
    led = SignedLedger(p, s)
    led.append("mount", checkpoint_fingerprint_sha256="a"*64, runtime_flags_sha256="b"*64, slot_manifest_digest=None)
    txt = p.read_text(); p.write_text(txt.replace("verified_mount","tamperedxxxx") if "verified_mount" in txt else txt[:-2]+"xx\n")
    try:
        led.append("rollback", checkpoint_fingerprint_sha256="a"*64, runtime_flags_sha256="b"*64, slot_manifest_digest=None)
        appended2 = True
    except Exception as e:
        appended2 = False
    try:
        LedgerVerifier.verify_file(p, s); verifies = True
    except Exception:
        verifies = False
    rec("P6_ledger_append_after_tamper", "PARTIAL" if appended2 else "CLOSED",
        f"append_after_tamper={appended2} verify_file_after={verifies} (next init would fail closed, live append forks)")

for line in out: print(line)
