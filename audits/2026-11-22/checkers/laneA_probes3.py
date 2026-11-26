#!/usr/bin/env python3
# Audit checker copy, 2026-11-22. Run from the repo root, for example: python3 -I -B audits/2026-11-22/checkers/<name>.py
# The repo root is derived from this file location. No edit is needed.
import sys, json, tempfile
from pathlib import Path
import pathlib as _pl
_R = _pl.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_R / "src"))
# Inline stdlib fakes only: this checker must run on a stdlib-only Python host
# (no pytest, no tests/ imports), like falsify_probe.py does.
from warp_modeld.experiment import ExperimentController, ReceiptLog, load_contract, CompileResult
contract = load_contract(_R / "experiments" / "demo-2026-11-22")
with tempfile.TemporaryDirectory() as td:
    logpath = Path(td)/"r.jsonl"
    seen = {}
    class FakeCompiler:
        def compile(self, cand, parent):
            return CompileResult(adapter_sha256="c"*64, command="x", command_version="v", timing_ms=1.0, compiler_repo=contract.compiler_repo, compiler_commit=contract.compiler_commit)
    class OrderRuntime:
        def mount_adapter(self, sha, scale):
            events = []
            if logpath.is_file():
                events = [json.loads(l).get("event") for l in logpath.read_text().splitlines() if l.strip()]
            seen["events_at_mount"] = events
            return 1.0
    class FakeLifecycle: pass
    ctl = ExperimentController(contract=contract, compiler=FakeCompiler(), runtime=OrderRuntime(),
        lifecycle=FakeLifecycle(), receipts=ReceiptLog(logpath), environment={})
    cand = ctl.propose({"eta": 0.01, "lora_scale": 1.0})
    ctl.compile_and_bind(cand, actual_parent_sha256=contract.parent_sha256)
    print(f"P8_mount_before_digest_record: events_at_mount={seen['events_at_mount']} digest_recorded_before_mount={'candidate_digest_recorded' in seen['events_at_mount']}")
# P9 cerebras bool/edges: rank True, strength True, rounds True, NaN measurement
from warp_modeld.cerebras_client import validate_candidate, validate_failure_report, validate_propose_context
from warp_modeld.errors import CerebrasSchemaError
def tryv(name, fn):
    try:
        r = fn(); print(f"{name}: ACCEPTED :: {r}")
    except Exception as e:
        print(f"{name}: CLOSED :: {type(e).__name__}: {str(e)[:90]}")
base = {"target_layer":"last","strength":0.5,"rank":8,"quantization":"q8_0"}
tryv("P9a_rank_True", lambda: validate_candidate({**base,"rank":True}))
tryv("P9b_strength_True", lambda: validate_candidate({**base,"strength":True}))
tryv("P9c_strength_tiny_denormal", lambda: validate_candidate({**base,"strength":5e-324}))
tryv("P9d_context_nan_constraint", lambda: validate_propose_context({"constraints":{"x":float("nan")}}))
tryv("P9e_context_huge_int_metric", lambda: validate_propose_context({"baseline_metrics":{"x":10**400}}))
tryv("P9f_candidate_extra_key_case", lambda: validate_candidate({**base,"Strength":0.5}))
