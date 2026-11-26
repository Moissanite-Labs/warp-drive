# Alpha readiness

This branch is an alpha candidate for the offline verifier. It is not a production release.

## Verified offline

Run from the repository root with Python 3.11 or newer:

```bash
PYTHONPATH=src python3 -m pytest -q tests/           # full offline suite (needs pytest)
PYTHONPATH=src python3 -B -m unittest discover -s tests  # stdlib unittest.TestCase modules
```

`tests/test_experiment_controller.py` (like the pytest-style `tests/test_experiment_contract.py`) imports `pytest` at module level, so the stdlib `unittest discover` invocation needs `pytest` installed just to import that module; the pytest-style test functions in those two modules are only collected by pytest itself. Observed in this tree (Python 3.13.5, pytest 9.2.0): `pytest -q tests/` reports `325 passed, 4 skipped` and `python3 -B -m unittest discover -s tests` reports `Ran 210 tests ... OK (skipped=4)`; with `SILIQUANT_CHECKER_PATH` pinned to a real `shape/check_certificate.py` the counts are `327 passed, 2 skipped` and `OK (skipped=2)`. The skips are the two opt-in live smoke tests plus the two real-checker tests when `SILIQUANT_CHECKER_PATH` is unset.

The SiliQuant bridge tests are deterministic offline tests. To include the real checker test, set `SILIQUANT_CHECKER_PATH` to the absolute path of a pinned `shape/check_certificate.py` checkout. No live model, paid provider, or network backend is required.

The alpha branch includes:

- Stage 4 fail-closed slot flushing. Missing `list_slots`, a non-callable `list_slots`, a dirty required bank, a dirty non-required bank, or a top-level state taint all prevent a `verified_clean` receipt.
- A SiliQuant bridge that requires verifier-owned expectations for quant_dtype, weft digest, codebook receipt digest, checker digest, picked arm, and budget. It returns the checked pick and provenance instead of a bare boolean.
- The original provider candidate schema. The model proposes configuration only. It does not supply acceptance evidence.

## Required deployment inputs

The core verifier needs real checkpoint, lineage, runtime, canary, and ledger values. The example config contains placeholders and is not usable as-is. Read `ARCHITECTURE.md` and `PLAN.md` before deployment. Keep the ledger key and canary suite under operator-owned paths. The daemon starts with:

```bash
warp-modeld serve --config /etc/warp/modeld.json
```

## Known limits

- Live Cerebras endpoint status is unverified. The default model id is not in the shared inference catalog. A dedicated endpoint id is required for any live test.
- Real llama-server/GGUF lifecycle, Linux image boot, bare-metal recovery, CUDA multi-adapter checks, and real Lattice hardware remain untested here.
- The SiliQuant codebook receipt proves the best predicted pick among supplied candidates. It does not prove Frobenius, spectral, leakage, safety, adapter quality, or model quality.
- Alpha promotion still requires an independent non-author review and a clean merge state. Do not merge on tests alone.
