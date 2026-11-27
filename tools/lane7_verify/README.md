# Lane 7 independent verifier

Independent checks for the warp-drive demo lanes (issue #7). The verifier
reads artifacts only: frozen contract files, published pilot receipts,
candidate receipts, and receipt logs. It never imports the controller
(`warp_modeld.experiment`) or any Warp runtime code, so its verdicts are
independent re-derivations, not re-runs of the code under audit.

## Run

From the repo root, with the frozen contract checked out at `--exp-dir`:

```sh
python3 tools/lane7_verify/verify.py all \
  --exp-dir experiments/demo-2026-11-22 \
  --harvest-meta harvest_v1.meta.json \
  --ml-manifest ml-manifest.json \
  --pilot server_logit_check_v2.json \
  --receipt receipt.json \
  --log receipts.jsonl \
  --schema schemas/cerebras-candidate.schema.json
```

Single checks: `contract`, `leakage`, `margins`, `receipt`,
`receipt-log`, `config-digests`, `cerebras-bounds`, `policy`. Each prints
one JSON object per check (`check`, `verdict`, `evidence`). Exit code is
0 when no check is FALSIFIED, 1 when any check is FALSIFIED, 2 on error.

## Tests

```sh
python3 -m pytest tools/lane7_verify/tests/test_lane7_verify.py -q
LANE7_EXP_DIR=<path to experiments/demo-2026-11-22> python3 -m pytest tools/lane7_verify/tests/test_lane7_verify.py -q
```

The second form also runs the golden-fixture test against the real frozen
contract. Fixtures in `tests/fixtures/` are a fake-runtime run of the
lane-5 controller: control flow and receipt shape only, never
adapted-model evidence. The fixture log is known to carry a NaN rollback
placeholder in its `evaluated` entry, which the verifier flags.

## What it does not do

It cannot verify live model behavior. There is no GPU, no local
checkpoint, no Cerebras credential, and no live llama-server on the
machine where the audit ran, so every empirical verdict on the real
checkpoint is UNVERIFIED here. Mocked runs prove schema and routing
only. See `AUDIT_LOG.md` for the full matrix, the evidence, and the
anomalies returned to the owning lanes.
