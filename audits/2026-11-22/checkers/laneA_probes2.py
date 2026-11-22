#!/usr/bin/env python3
# Audit checker copy, 2026-11-22. Run from the repo root, for example: python3 -I -B audits/2026-11-22/checkers/<name>.py
# The repo root is derived from this file location. No edit is needed.
import sys, json, tempfile
from pathlib import Path
import pathlib as _pl
_R = _pl.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_R / "src")); sys.path.insert(0, str(_R / "tests"))
out=[]
def rec(n,v,d): out.append(f"{n}: {v} :: {d}")
# P5b parser: scale as string "nan"/"inf" via real list_lora_adapters with stubbed _request
from warp_modeld.llama_client import LlamaServerClient
c = LlamaServerClient.__new__(LlamaServerClient)
c._request = lambda m,p,b=None: [{"id": 3, "path": "/a.gguf", "scale": "nan"}]
a = c.list_lora_adapters()[0]
rec("P5b_parser_nan_scale", "FAIL-OPEN-CONFIRMED" if a.scale!=a.scale else "CLOSED", f"parsed scale={a.scale!r} id={a.id}; int(True) style coercion also unguarded")
c._request = lambda m,p,b=None: [{"id": True, "path": "/a.gguf", "scale": 0.5}]
b = c.list_lora_adapters()[0]
rec("P5c_bool_adapter_id", "CONFIRMED-COERCION" if b.id==1 else "CLOSED", f"bool id coerced to {b.id}")
# P7 Step1 no file: verify_stage1 succeeds with adapter_path=None
import helpers
bundle_d = helpers.make_adapter_bundle_dict()
from warp_modeld.fingerprint import AdapterBundle, verify_stage1
bundle = AdapterBundle.from_dict(bundle_d)
rep = verify_stage1(bundle, helpers.make_checkpoint(), helpers.make_lineage(), helpers.make_runtime_flags())
rec("P7_stage1_no_file", "DOCUMENTED-SKIP" , f"adapter_path={bundle.adapter_path} adapter_file_verified={rep.adapter_file_verified} report_returned=True")
# P8 compile_and_bind ordering: mount before digest recorded
# Use controller test fakes if importable
try:
    import test_experiment_controller as tc
    names=[n for n in dir(tc) if "Fake" in n or "fake" in n.lower()]
    rec("P8_order_fakes", "INFO", f"fakes={names[:8]}")
except Exception as e:
    rec("P8_order_fakes", "ERR", str(e)[:100])
for l in out: print(l)
