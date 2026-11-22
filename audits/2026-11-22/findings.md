# Findings, 2026-11-22

Head for all sections: 063aaeeba9638c51c7f3fbb4ea86d5af11a3ee67.

Each section gives witness, observed output, steelmanned reading, and fix owner surface.

## F1. Stage 2 certificate is self attested

- Severity: High. Class: Exact. Owner surface: src/warp_modeld/certificate.py and src/warp_modeld/verifier.py.
- Witness: FixedRadixCertificate.create with invented metrics. Frobenius value 1. Radix value 2 to the 20. Adapter hash set to free text hex.
- Observed output: verify_division_free returns passed True. Probe line: P1a_forged_cert FAIL-OPEN-CONFIRMED.
- Code facts: certificate.py sets cert hash as sha256 of the body. Verify checks the self hash plus bounds only. No signer check exists.
- Closed edge: bool metric values fail. Code requires exact int type.
- Steelmanned reading: a trusted compiler receipt model would make self attestation a stated boundary. No such boundary is stated in the module or in the architecture Stage 2 text.
- Caller fact: mount_stack in verifier.py line 393 takes bundles from the same caller. Stage 2 adds no separation against that caller.
- Fix direction: sign certificates or bind them to a trusted compiler receipt. Record the trust rule in the architecture text.

## F2. Stage 1 file binding is optional on the library path

- Severity: High. Class: Exact. Owner surface: src/warp_modeld/fingerprint.py, verifier.py, cli.py.
- Witness: verify_stage1 with adapter_path None. No file exists at any claimed path.
- Observed output: success with adapter_file_verified False. mount_stack ignores the flag.
- Code facts: fingerprint.py lines 844 to 855 skip the file hash on None. verifier.py line 246 hashes only when a path exists on disk.
- Default facts: WarpModeld default require_loaded_adapter_files is False at verifier.py line 88. CLI config default is True at cli.py line 57.
- Steelmanned reading: the CLI path is hardened. The library default may be a simulation boundary. The split is not marked as such.
- Fix direction: set the library default to True, or reject unverified files unless the caller opts out in writing.

## F3. Acceptance policy returns ACCEPT on NaN scalar gates

- Severity: Medium. Class: Exact. Owner surface: src/warp_modeld/experiment.py.
- Witness: Measurements with NaN in task_top1, contested, break_count, iid_kl, agreement, shifted_kl. Demo thresholds in use.
- Observed output: verdict ACCEPT, failed list empty. Probe line: P2_nan_policy FAIL-OPEN-CONFIRMED.
- Code facts: apply_acceptance_policy at experiment.py line 726. Each NaN comparison is False. No gate fires.
- Narrowing: margin NaN fails closed through all() checks near lines 781 and 801. Rollback diff NaN fails closed near line 852.
- Controller fact: the raw path rejects non finite numbers through _require_number near lines 167 to 170.
- Steelmanned reading: guarded construction is safe. Direct construction is public API. The function sits in __all__ and in __init__ exports.
- Fix direction: reject non finite values inside apply_acceptance_policy itself.

## F4. Receipt log append does not verify the chain

- Severity: Medium. Class: Exact. Owner surface: src/warp_modeld/experiment.py ReceiptLog.
- Witness: tamper one entry so verify_chain returns False. Then call append.
- Observed output: append succeeds. The new entry extends the tampered head. verify_chain still returns False.
- Code facts: append near lines 955 to 959 reads prev entry hash with no recompute. run_experiment seals but never calls verify.
- Steelmanned reading: verify and verify_chain exist for consumers. Tests assert them. The write path still fails open.
- Fix direction: verify the tail hash before append, or verify the chain on open and fail closed.

## F5. Missing slot listing reads as clean

- Severity: Low. Class: Exact. Owner surface: src/warp_modeld/canary.py.
- Witness: a fake client with no list_slots attribute. Call _is_slot_clean_for_banks.
- Observed output: True. The slot reads clean with no evidence.
- Code facts: canary.py lines 416 to 417 return True when the attribute is absent. The real client has list_slots at llama_client.py line 199.
- Steelmanned reading: duck typing helps test fakes. Live impact needs a malformed client.
- Fix direction: return False when slot state cannot be listed.

## F6. llama client coercions accept NaN scale and bool id

- Severity: Low. Class: Exact. Owner surface: src/warp_modeld/llama_client.py.
- Witness: list_lora_adapters with scale given as the string nan. Adapter id given as JSON true.
- Observed output: scale nan accepted, id 1 accepted. abs(nan) greater than 0 is False. Scale guards in canary.py near lines 519 and 773 do not fire.
- Narrowing: bare NaN JSON tokens fail at parse near lines 110 to 111 and 161. Reach needs string typed scale. Bool id needs only plain JSON true.
- Added by verifier: set_lora_adapters near line 195 uses the same unguarded int and float coercions.
- Steelmanned reading: the backend is local and trusted. This is depth of defense, not a live exploit by itself.
- Fix direction: require exact numeric types and finite scales in both list and set paths.

## F7. Controller mounts before digest record

- Severity: Medium. Class: Exact. Owner surface: src/warp_modeld/experiment.py compile_and_bind.
- Witness: fake compiler and runtime. Record event order around mount_adapter.
- Observed output: order is candidate_proposed, mount, candidate_digest_recorded. Events at mount hold no digest record.
- Code facts: mount near line 1194. Digest append near line 1200. Comment near lines 1191 to 1193 states ordering intent.
- Steelmanned reading: hash_recorded_before_evaluation holds in the literal sense. Evaluation runs after the record.
- Risk window: a crash after mount leaves a live adapter with no digest record.
- Fix direction: append the digest record before mount, or rollback the mount when the append fails.

## F8. Kill switch does not gate base inference

- Severity: Question. Class: Exact code fact. Owner surface: src/warp_modeld/verifier.py.
- Witness: read infer and complete near lines 704 and 759. Read mount_stack near lines 410 to 415.
- Observed output: mount checks the kill switch. Inference paths do not. Guards there are quarantine, stale, zone, and lora override only.
- Steelmanned reading: base model inference after rollback may be intended. The kill switch error text speaks of adapter mounts.
- State: no defect verdict. A product call is required. See issues.md.
- Fix direction: record the intended scope in docs. Add gates only if the scope includes base inference.

## F9. Signed ledger live append trusts memory head

- Severity: Low. Class: Exact. Owner surface: src/warp_modeld/ledger.py.
- Witness: open a SignedLedger. Tamper the file on disk. Call append on the live handle.
- Observed output: append succeeds. LedgerVerifier.verify_file then raises LedgerTamperError.
- Code facts: append near line 347 trusts the in memory prev hash. Init near line 331 verifies. Next open fails closed by code read.
- Steelmanned reading: detection exists at open and verify time. The live window is the gap.
- Fix direction: recheck the tail hash before append, or document single writer ownership as a contract rule.

## F10. Cerebras context accepts NaN constraint

- Severity: Low. Class: Exact. Owner surface: src/warp_modeld/cerebras_client.py.
- Witness: validate_propose_context with a NaN constraint float. Then encode the payload.
- Observed output: validation passes. json.dumps near line 637 emits bare NaN. No allow_nan False is set.
- Narrowing: baseline metric NaN fails through _is_number near lines 171 to 175. Constraint floats near lines 330 to 337 lack that check.
- Closed edges: bool rank and bool strength fail. Huge int metric fails. Extra candidate keys fail. Model echo check exists.
- Steelmanned reading: live support is marked unverified in docs. The gap is a data hygiene defect.
- Fix direction: reject non finite floats in constraints. Set allow_nan False on all dumps calls.

## S1. Receipt schema file fails schema check

- Severity: Medium. Class: Exact. Owner surface: experiments/demo-2026-11-22/receipt.schema.json.
- Witness: run jsonschema check_schema on the file under draft 07 and draft 2020-12.
- Observed output: SchemaError. The value 0.1.0 is not of type object or boolean. Any validate call then fails on a str attribute error.
- Code fact: properties.receipt_schema_version is the bare string 0.1.0. A schema needs an object there.
- Steelmanned reading: the intent is const 0.1.0. With {"const": "0.1.0"} the file passes draft 07. A full hand receipt then validates.
- Digest fact: the file digest 009a148e still matches the manifest. The digest gate passes while the schema cannot load.
- Code fact: no jsonschema call site exists in src or tests. The two files under schemas/ load clean but enforce nothing by themselves.
- Fix direction: write the const object form. Bump the manifest in a versioned step. Add one validate call in tests.

## D1. README test count line is stale

- Severity: Low. Class: Exact. Owner surface: README.md line 77.
- Witness: read line 77. Run both suite commands at the head.
- Observed output: line 77 says 53 passing tests plus 1 opt in live test. Observed runs give 218 passed plus 2 skipped by pytest, and 128 ok by unittest.
- Runner fact: README line 41 tells readers to run unittest discover. Counted claims elsewhere name pytest. Counts differ by runner.
- Steelmanned reading: the line was true at its first commit. Growth made it stale.
- Fix direction: state runner and counts that match main today. Name both live skips.

## D2. README live timing line has no run record in repo

- Severity: Medium. Class: Anchor. Owner surface: README.md line 79.
- Witness: search the repo for 16.71, 4.90, 4.22, 84384. List tracked gguf, log, jsonl files.
- Observed output: hits sit in README line 79 only. Tracked run files count 0.
- Harness fact: tests/test_live_llama_smoke.py exists. It builds 5 live canaries and asserts stage time under 5 ms. It does not pin 16.71 us.
- Steelmanned reading: a real run may exist on another host. This repo holds no receipt for it.
- Fix direction: commit a run receipt, or mark the line as a past host result with date and host.

## C1. PR 41 contains PR 37 and both stay open

- Severity: High. Class: Exact. Owner surface: merge queue for PR 37 and PR 41.
- Witness: full paginated file lists. PR 37 has 3 files. PR 41 has 8 files.
- Observed output: overlap is canary.py, verifier.py, tests/test_trust_boundary_residuals_31.py. PR 37 is a subset of PR 41.
- Review facts: PR 37 latest review is CHANGES_REQUESTED at its head e39c6ba. No push answers it. PR 41 has 0 reviews.
- Close facts: PR 37 closes issues 16, 19, 31. PR 41 closes none. Merging PR 41 alone leaves those issues open.
- Steelmanned reading: PR 41 body states it carries PR 37 plus review fixes. Lineage is clear. Review state is not.
- Fix direction: pick one owner. Review it fresh. Close the other with a pointer.

## C2. Merge gate has no required checks and no suite run

- Severity: Medium. Class: Exact. Owner surface: org ruleset 27494833 and repo workflows.
- Witness: read the ruleset body. List workflows on main. Read check rollups on open heads.
- Observed output: rules are deletion, non fast forward, and pull request with 1 approval. No required status checks rule exists.
- Workflow facts: main has no .github folder. Heads show CodeQL success only. PR 42 adds one site gate from its own branch.
- Steelmanned reading: review approval is required and stale reviews dismiss on push. Test evidence still rests on reviewer runs.
- Fix direction: add a suite workflow on main. Require it in the ruleset.

## C3. Label needs decision is missing and two issues lack an owner

- Severity: Low. Class: Exact. Owner surface: repo labels and issue triage.
- Witness: list labels. List open issues and closing refs.
- Observed output: 10 labels, all GitHub defaults. The needs decision label is absent. No open issue or pull request carries any label.
- Owner facts: issue 39 asks a design question and has no pull request. Issue 6 has no open pull request owner by refs.
- Steelmanned reading: triage may run off GitHub. The repo surface does not show it.
- Fix direction: create the label. Add it to issues that need a human call. Close or own issues 6 and 39.
