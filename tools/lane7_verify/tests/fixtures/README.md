# Golden fixtures (generated, not hand-written)

Produced by `tools/lane7_verify/tests/generate_fixtures.py`, which runs
the repo's own fake controller — the `FakeCompiler` / `FakeRuntime` /
`FakeLifecycle` adapters copied verbatim from
`tests/test_experiment_controller.py` — against the frozen contract at
`experiments/demo-2026-11-22`, via:

    PYTHONPATH=src python3 -B tools/lane7_verify/tests/generate_fixtures.py \
        --exp-dir experiments/demo-2026-11-22 \
        --out tools/lane7_verify/tests/fixtures

The run used fake compiler, runtime, and lifecycle adapters, so these
files prove control flow and receipt shape only, never adapted-model
evidence: no checkpoint, GPU, or live server is touched. The generator
normalizes the wall-clock fields (`ts_utc`, `evaluate_ms`, `compile_ms`)
to fixed values and recomputes the log hash chain and seal, so repeated
runs are byte-identical (verified by diffing two independent runs).

`receipt.json` pins the current `experiments/demo-2026-11-22`
`manifest.json` sha256 and carries 84 adapter / 36 baseline margins,
matching the frozen request counts, so `verify.py receipt` and
`verify.py policy` return VERIFIED against that contract directory.
`receipts.jsonl` is the controller's hash-chained, sealed 7-entry log
(candidate_proposed, candidate_digest_recorded, evaluated,
rollback_verified, verdict, receipt, sealed); it is strict JSON, so
`verify.py receipt-log` and `verify.py config-digests` return VERIFIED.

Verdict of the generating run: ACCEPT, candidate `cand-e08705d50d27`.

Note: `generate_fixtures.py` is a fixture generator, not part of the
verifier. The verifier (`tools/lane7_verify/verify.py`) stays
zero-import from `warp_modeld`; see `test_no_controller_import`.
