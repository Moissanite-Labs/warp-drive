# Issue drafts, 2026-11-22

Nothing below has been filed. Copy one draft block at a time.

Each draft follows the same shape: title, labels line, body.

---

## Draft F1: Stage 2 certificate is self attested

**Title:** Stage 2 certificate accepts invented metrics (self hash only)

**Labels:** bug, needs decision

**Body:**

`FixedRadixCertificate.create` followed by `verify_division_free` accepts invented metrics for any adapter hash. The certificate hash is `sha256(body)`. Verify checks that self hash plus bounds. No signer check exists.

Reproducer: run `python3 -I -B audits/2026-11-22/checkers/laneA_probes.py`. Line `P1a_forged_cert` shows a pass with frobenius 1 and radix 2^20.

Acceptance check: a certificate with invented metrics fails verify unless it carries a trusted signature or receipt. The trust rule is written in ARCHITECTURE.md. Suite stays green.

> Automated posting by agentic team with human oversight.

---

## Draft F2: Stage 1 file binding is optional on the library path

**Title:** Library default mount path never hashes the claimed adapter file

**Labels:** bug

**Body:**

`verify_stage1` with `adapter_path=None` returns success with `adapter_file_verified=False`. `mount_stack` ignores the flag. `WarpModeld` defaults `require_loaded_adapter_files=False`. The CLI default is True. The library path can mount with no file hash at all.

Reproducer: run `python3 -I -B audits/2026-11-22/checkers/laneA_probes2.py`. Line `P7_stage1_no_file` shows the skip.

Acceptance check: a default library mount with a missing adapter file fails closed. An explicit opt out exists for simulation use and is named in docs.

> Automated posting by agentic team with human oversight.

---

## Draft F3: Acceptance policy returns ACCEPT on NaN scalar gates

**Title:** apply_acceptance_policy returns ACCEPT when scalar gates are NaN

**Labels:** bug

**Body:**

`apply_acceptance_policy` in `experiment.py` returns ACCEPT with an empty failed list when `task_top1`, `contested`, break count, `iid_kl`, `agreement`, and `shifted_kl` are NaN. Each NaN comparison is False, so no gate fires. The function is public API. The controller raw path already rejects non finite numbers. Direct construction does not.

Reproducer: run `python3 -I -B audits/2026-11-22/checkers/laneA_probes.py`. Line `P2_nan_policy` shows ACCEPT.

Acceptance check: any non finite scalar in Measurements yields a failed gate result or a clear error from the policy function itself.

> Automated posting by agentic team with human oversight.

---

## Draft F4: Receipt log append does not verify the chain

**Title:** ReceiptLog.append extends a tampered chain without error

**Labels:** bug

**Body:**

`ReceiptLog.append` reads the previous entry hash and never recomputes it. After tampering, `verify_chain` returns False and `append` still succeeds. `run_experiment` seals the log but never calls `verify`. The log is unsigned, so a full rewrite plus seal cannot be detected by the write path.

Reproducer: run `python3 -I -B audits/2026-11-22/checkers/falsify_probe.py` and check the F4 lines.

Acceptance check: append on a tampered log fails closed. A test tampers one entry and asserts append raises.

> Automated posting by agentic team with human oversight.

---

## Draft F5: Missing slot listing reads as clean

**Title:** _is_slot_clean_for_banks returns True when slots cannot be listed

**Labels:** bug

**Body:**

`_is_slot_clean_for_banks` in `canary.py` returns True when the client has no `list_slots` attribute. A slot with no listing evidence reads clean. The real `LlamaServerClient` has `list_slots`, so the gap needs a fake or malformed client.

Reproducer: run `python3 -I -B audits/2026-11-22/checkers/falsify_probe.py` and check the F5 line with a no-slots client.

Acceptance check: a client with no slot listing reads not clean. A test covers the missing attribute case.

> Automated posting by agentic team with human oversight.

---

## Draft F6: llama client coercions accept NaN scale and bool id

**Title:** list/set LoRA adapters coerce bool ids and NaN scales

**Labels:** bug

**Body:**

`list_lora_adapters` coerces `int(True)` to 1 and `float("nan")` to NaN with no type or finite check. A NaN scale makes `abs(scale) > 0.0` False, so unverified adapter scale guards do not fire. `set_lora_adapters` uses the same coercions. Bare NaN JSON tokens are already rejected at parse, so scale reach needs a string typed value. Bool id reach needs only plain JSON true.

Reproducer: run `python3 -I -B audits/2026-11-22/checkers/laneA_probes2.py`. Lines `P5b` and `P5c` show both coercions.

Acceptance check: bool ids and non finite scales raise a clear client error in both list and set paths.

> Automated posting by agentic team with human oversight.

---

## Draft F7: Controller mounts before digest record

**Title:** compile_and_bind mounts the adapter before the digest record exists

**Labels:** bug

**Body:**

`ExperimentController.compile_and_bind` calls `runtime.mount_adapter` while the receipt log holds only `candidate_proposed`. The `candidate_digest_recorded` entry is appended after the mount. A crash in that window leaves a live adapter with no digest record. The `hash_recorded_before_evaluation` check still passes in the literal sense, since evaluation runs later.

Reproducer: run `python3 -I -B audits/2026-11-22/checkers/laneA_probes3.py`. Line `P8_mount_before_digest_record` shows the order.

Acceptance check: the digest record precedes the mount call, or a failed append rolls the mount back. A test asserts event order.

> Automated posting by agentic team with human oversight.

---

## Draft F8: Kill switch scope for base inference

**Title:** Decide whether the kill switch must block base model inference

**Labels:** question, needs decision

**Body:**

The kill switch gates adapter mounts in `mount_stack`. The `infer` and `complete` paths do not check it. After a kill switch event, base model (W0) inference still runs. That may be intended, since rollback leaves the base model. The intended scope is not written down.

Question for a human call: should kill switch engaged, or learning disabled, also block base inference?

Acceptance check: the chosen scope is written in ARCHITECTURE.md. Code and tests match the written scope.

> Automated posting by agentic team with human oversight.

---

## Draft F9: Signed ledger live append trusts memory head

**Title:** SignedLedger.append succeeds after on-disk tampering in the same session

**Labels:** bug

**Body:**

`SignedLedger.append` trusts the in memory previous hash. If the file is tampered after open, append still succeeds. `LedgerVerifier.verify_file` then fails, and the next open fails closed. Detection exists. The live append window is the gap.

Reproducer: run `python3 -I -B audits/2026-11-22/checkers/falsify_probe.py` and check the F9 lines.

Acceptance check: append rechecks the on-disk tail hash and fails closed on mismatch, or single writer ownership is stated as a contract rule with a test.

> Automated posting by agentic team with human oversight.

---

## Draft F10: Cerebras context accepts NaN constraint

**Title:** validate_propose_context accepts NaN constraints and emits bare NaN JSON

**Labels:** bug

**Body:**

`validate_propose_context` accepts a NaN float in constraints. The payload encode uses `json.dumps` with no `allow_nan=False`, so a bare NaN token can go upstream. Baseline metrics already reject NaN through `_is_number`. Constraint floats do not.

Reproducer: run `python3 -I -B audits/2026-11-22/checkers/laneA_probes3.py` and check the P9 lines.

Acceptance check: non finite constraint floats fail validation. All `json.dumps` calls on outbound payloads set `allow_nan=False`.

> Automated posting by agentic team with human oversight.

---

## Draft S1: Receipt schema file fails schema check

**Title:** experiments demo receipt.schema.json cannot be loaded by a validator

**Labels:** bug

**Body:**

`experiments/demo-2026-11-22/receipt.schema.json` sets `properties.receipt_schema_version` to the bare string `"0.1.0"`. JSON Schema requires an object or boolean there. `check_schema` raises SchemaError, and any validate call fails. The file digest still matches the demo manifest, so the digest gate passes while the schema cannot load. No `jsonschema` call site exists in `src` or `tests`.

Reproducer: run `python3 -I -B audits/2026-11-22/checkers/laneB_checker.py .` and check the schema rows. The repaired form `{"const": "0.1.0"}` passes.

Acceptance check: `check_schema` passes for the committed file. A test validates one emitted receipt. The manifest bump is versioned.

> Automated posting by agentic team with human oversight.

---

## Draft D1: README test count line is stale

**Title:** README line 77 test counts no longer match main

**Labels:** documentation

**Body:**

README line 77 says 53 passing tests plus 1 opt in live test. At main 063aaee, `PYTHONPATH=src pytest tests/` gives 218 passed and 2 skipped. `unittest discover` gives Ran 128, OK, skipped 2. The two skips are both opt in live tests. README line 41 tells readers to use unittest, while counted claims elsewhere name pytest.

Reproducer: read README line 77, then run both commands above.

Acceptance check: README names the runner and states counts that match a fresh run on main.

> Automated posting by agentic team with human oversight.

---

## Draft D2: README live timing line has no run record in repo

**Title:** README line 79 live run numbers have no receipt in this repo

**Labels:** documentation, needs decision

**Body:**

README line 79 states live numbers: Stage 2 in 16.71 us, 5 canaries in 4.90 s, kill plus erase in 4.22 ms, an 84,384 byte LoRA, bit exact base output. A repo search finds those numbers in README line 79 only. No gguf, log, or jsonl run file is tracked. The live smoke test exists and asserts stage time under 5 ms. It does not pin 16.71 us.

Question for a human call: publish the run receipt, or mark the line as a dated past host result?

Acceptance check: the line either links a committed run receipt or carries a clear past host label with date and host.

> Automated posting by agentic team with human oversight.

---

## Draft C1: PR 41 contains PR 37 and both stay open

**Title:** PR 41 contains PR 37 in full. Pick one owner for issues 16, 19, 31

**Labels:** bug

**Body:**

PR 37 changes 3 files: `canary.py`, `verifier.py`, `tests/test_trust_boundary_residuals_31.py`. All 3 sit inside PR 41. PR 37 has a CHANGES_REQUESTED review at its head with no answering push. PR 41 has no reviews. Only PR 37 carries closing words for issues 16, 19, and 31. Merging PR 41 alone would not close them.

Reproducer: compare paginated file lists for PR 37 and PR 41. Overlap count is 3. Subset check is true.

Acceptance check: one pull request owns the fix and gains a fresh approval. The other closes with a pointer to the owner.

> Automated posting by agentic team with human oversight.

---

## Draft C2: Merge gate has no required checks and no suite run

**Title:** Main can merge with no test suite run on GitHub

**Labels:** enhancement

**Body:**

Ruleset 27494833 requires 1 approval and blocks deletion and non fast forward pushes. It has no required status checks rule. Main has no workflows folder. Open heads show CodeQL success only. No suite check runs on GitHub for any head.

Reproducer: read the ruleset body and the check rollup for any open head. Check names are CodeQL entries only.

Acceptance check: a suite workflow runs on pull requests to main. The ruleset requires that check before merge.

> Automated posting by agentic team with human oversight.

---

## Draft C3: Missing decision label and unowned issues

**Title:** Add the needs decision label and assign owners for issues 6 and 39

**Labels:** enhancement

**Body:**

The repo has 10 labels, all GitHub defaults. The `needs decision` label is missing. No open issue or pull request carries any label. Issue 39 asks a design question and has no pull request. Issue 6 has no open pull request owner by GitHub refs.

Reproducer: list labels, then list open issues with closing refs.

Acceptance check: the label exists. Issues that need a human call carry it. Issues 6 and 39 each have an owner or a close note.

> Automated posting by agentic team with human oversight.
