# Final independent non-author evidence review

## Tooling verdict

**APPROVE.** The completed record supports `REFERENCE_REPLAY_COMPLETE` as an `N0`, `reference_replay` tooling result. I found no blocking defect in the locked bindings, receipts, stored-output classifications, counts, parity claims, expected-failure handling, public hygiene, or stated limits.

This is not approval of Cave's scientific method, a full-seed result, real-data readiness, a live-model result, or a novelty claim above `N0`. Real-data readiness remains `BLOCKED`.

## Independence and scope

I did not author the runner. This was an automated, non-author review using the judgment model `cerebras/moonshotai-kimi-k3.1-pro-trial`.

I read `PREREG.md`, `PROTOCOL.md`, `LOCK.json`, `cases.json`, every evaluation source, `RESULTS.md`, the earlier review records, all of `runs/run-001`, and the pinned Cave plan, smoke record, blocker record, and known-answer imports. I independently recomputed the lock and evidence bindings without importing the evaluator, ran the locked controls and checker in all three modes, inspected raw stdout and stderr, and inspected the Cave commit and worktree.

I did not rerun any Cave target case, call a model, use paid compute, access the network, or write GitHub. I did not change receipts, outputs, locks, cases, evaluation code, or target files. The only POC file written by this review is this report.

Paths below use `<POC>` for the POC root and `<CAVE_CHECKOUT>` for the pinned Cave checkout. Substitute those locally when replaying the commands.

## Environment and pinned target

From `<POC>`:

```bash
python3 -I -B -c 'import sys, numpy; print(sys.version.split()[0]); print(numpy.__version__)'
```

Observed:

```text
3.14.6
2.5.4
```

From `<CAVE_CHECKOUT>`:

```bash
git rev-parse HEAD
git rev-parse --verify HEAD^{commit}
git status --porcelain=v1 --untracked-files=all
git diff --exit-code
git diff --cached --exit-code
git show -s --format='%H%n%T%n%P%n%an%n%ai%n%s' HEAD
```

Both commit queries returned exactly `a714ef7981421266bea78e8357d61f3586f0eda0`. Status was empty and both diffs returned zero. The commit tree was `dc823affff9b7c9fd3dae3e37f9847732bf13c02`, parent `8d54eb11ceb8ce5e7706efd51d60bdd61b079a77`, subject `Implement Amendment 2 in the code and smoke-run it`. A final status check after all read-only probes remained empty at the same commit. No bytecode or cache directory appeared in the target.

## Locked-file and evidence hashes

I independently hashed raw bytes with `shasum -a 256` from `<POC>` and separately recomputed them in Python:

```bash
shasum -a 256 PREREG.md PROTOCOL.md LOCK.json cases.json RESULTS.md \
  evaluation/check_receipts.py evaluation/make_lock.py evaluation/run.py \
  evaluation/test_harness.py runs/run-001/receipts.jsonl \
  runs/run-001/SUMMARY.json runs/run-001/SOURCE.json
```

| File | Independently observed SHA-256 |
|---|---|
| `PREREG.md` | `fd4e686f4885c0e221bbf87b850576a6dfcd35699fd0dec22e2f9c7d69cc680d` |
| `PROTOCOL.md` | `46c55dafb64f1264dc4ce1e61b21e8952c7bd0da7d995a4f0be099965e90c1d1` |
| `cases.json` | `d8616d8708ea98c5b4704964ecdcde0d3e3bc11e17e66d6741fc6d29d5ba66d0` |
| `evaluation/check_receipts.py` | `c19315fdc2811ce715ceed195cae1173b00ce094b3894667789cc551ba29d18b` |
| `evaluation/make_lock.py` | `8788a4a3e5859dc8e8143cef7f9c92ca5a6a264a4430116fad3a2da457ce874f` |
| `evaluation/run.py` | `539c99d0cada9d8de84da79232f40ef725a5acfc9d8bd99bce78aa92767b64c8` |
| `evaluation/test_harness.py` | `fc6fad7e6b24cd62463a20b4a149108187e76b6c054d149a8148b46e2bfb6b5b` |
| `LOCK.json` | `9f1c5cd103696d342b2b152de8058cde278e371d980526b5db6e3e08946f6466` |
| `RESULTS.md` before this review file existed | `05587abd21aeda820bb072805e45f0653b77fe9648af5411aa66b4281a104ef6` |
| `runs/run-001/receipts.jsonl` | `f98227b4c1b8ad5e102a078950ed88a74733a964762b27150e570d889fe80573` |
| `runs/run-001/SUMMARY.json` | `6f0c9358e2ad257c2161d21a350f4b00b5d4b2af1f0ec51eff41d07bd74ca019` |
| `runs/run-001/SOURCE.json` | `3f11ddce2d65aee9f5a868b3492c1103adf170ae3e6cc63334f09421518f343d` |

All seven hashes in `LOCK.json` matched. The lock's case digest, Cave commit, and Aletheia commit matched `cases.json`. Every receipt and `SOURCE.json` carried the observed lock digest. `SUMMARY.json` also carried that lock digest and the pinned Cave commit.

## Harness controls in all three modes

From `<POC>`, I ran these commands separately:

```bash
python3 -I -B evaluation/test_harness.py
python3 -I -O -B evaluation/test_harness.py
python3 -I -B -W error evaluation/test_harness.py
```

Observed results:

| Mode | Tests | Failures | Errors | Skips | Result |
|---|---:|---:|---:|---:|---|
| plain | 19 | 0 | 0 | 0 | `OK` |
| optimized | 19 | 0 | 0 | 0 | `OK` |
| warnings-as-errors | 19 | 0 | 0 | 0 | `OK` |

This independently confirms 57 passing control executions. A separate AST inspection found zero bare Python assertions in all four locked Python sources.

## Locked receipt checker in all three modes

From `<POC>`, with `<CAVE_CHECKOUT>` substituted literally by the local shell:

```bash
python3 -I -B evaluation/check_receipts.py --target <CAVE_CHECKOUT> --run runs/run-001
python3 -I -O -B evaluation/check_receipts.py --target <CAVE_CHECKOUT> --run runs/run-001
python3 -I -B -W error evaluation/check_receipts.py --target <CAVE_CHECKOUT> --run runs/run-001
```

Each returned zero and printed the same JSON:

```json
{"chain_valid":true,"outcome_counts":{"fail":2,"operational_failure":3,"pass":13},"receipt_count":18,"status":"REFERENCE_REPLAY_COMPLETE"}
```

## Independent chain, binding, and byte audit

I also ran an inline `python3 -I -B` auditor from `<POC>` that used only `pathlib`, `hashlib`, `json`, `re`, and `collections`. It imported nothing from `evaluation/`. Appendix A reproduces the complete executed command and body.

The auditor directly performed the following checks rather than delegating them to `verify_run`:

- Strictly parsed the lock, cases, 18 receipt lines, source, and summary; rejected duplicate keys, floats, and non-finite numbers.
- Recomputed all seven locked hashes and the lock digest from bytes.
- Recomputed every receipt digest from canonical JSON after removing only its self-digest field, then checked sequence and previous-digest linkage from `null` through sequence 17.
- Re-derived the ordered case-mode matrix, commands, arguments, smoke flags, timeouts, oracle classes, expected outcomes, output names, target commit, and lock binding from `cases.json`.
- Hashed all 36 stdout/stderr files and recomputed every observed outcome from its raw terminal marker and return code.
- Recomputed all outcome counts, match flags, five parity groups, terminal receipt digest, and the complete expected summary object.
- Checked the exact 39-file flat run manifest, with no directory or symbolic link entries.
- Independently checked the U01, R01, K1, K2, K3, K4, K5, and K6 content counts quoted below.

Its terminal JSON was:

```json
{"independent_checks":"PASS","k5_summaries_per_mode":0,"k6_mutants_per_mode":7,"k6_refusal_codes_per_mode":6,"lock_sha256":"9f1c5cd103696d342b2b152de8058cde278e371d980526b5db6e3e08946f6466","locked_files":7,"manifest_files":39,"outcome_counts":{"fail":2,"operational_failure":3,"pass":13},"parity":[{"case":"K1","modes":["plain","optimized","warnings"],"stdout_and_outcome_equal":true},{"case":"K5","modes":["plain","optimized","warnings"],"stdout_and_outcome_equal":true},{"case":"K6","modes":["plain","optimized","warnings"],"stdout_and_outcome_equal":true},{"case":"R01","modes":["plain","optimized","warnings"],"stdout_and_outcome_equal":true},{"case":"U01","modes":["plain","optimized","warnings"],"stdout_and_outcome_equal":true}],"receipt_log_sha256":"f98227b4c1b8ad5e102a078950ed88a74733a964762b27150e570d889fe80573","receipts":18,"source_sha256":"3f11ddce2d65aee9f5a868b3492c1103adf170ae3e6cc63334f09421518f343d","summary_sha256":"6f0c9358e2ad257c2161d21a350f4b00b5d4b2af1f0ec51eff41d07bd74ca019","terminal_receipt_sha256":"a613eafb93c4fc44867f20102a1dda393c596835a4455e3142023b155ee2c1d7"}
```

The independently recomputed terminal receipt is exactly the digest reported by `RESULTS.md`: `a613eafb93c4fc44867f20102a1dda393c596835a4455e3142023b155ee2c1d7`.

## Raw output and count review

I inspected every stored stdout tail and every nonempty stderr. All receipts have `matched:true`, `timed_out:false`, nonnegative integer elapsed times, and return codes consistent with their classifications.

| Case | Locked modes | Direct raw-output finding |
|---|---|---|
| U01 | 3 | Each ends with the unique line `UNIT CHECKS: 336 checks, 0 failed`, then the separate line `PASS`; return code 0. |
| R01 | 3 | Each ends with exactly one `UNGUARDED: none`; return code 0. |
| K1 | 3 | Each reports 7,614 main checks, zero failures, zero non-representable cases, and four flagged must-fail controls with 95, 106, 4,762, and 30 failing checks. |
| K2 | plain only | Return code 1. The terminal summary is `FAIL`; K2a, K2b, and the control are all false. The control rejects 4 of 10 against a flag point of 5 of 10. |
| K3 | plain only | Return code 1. One gating cell, logistic `sub2`, is below criterion at 3 of 10; the circular-shift control is flagged at 1 of 10 against bound 1. |
| K4 | plain only | Return code 0. A>B is 9 of 10, A>C is 10 of 10, A-to-A-prime arrow and profile controls are both zero, and the separate blind spot is 0 of 20 seed-directions. |
| K5 | 3 | Return code 1 and no `SUMMARY` line in any mode. Plain and optimized stop with `GATE_MISSING` after overflow; warnings mode stops at the promoted overflow `RuntimeWarning`. All three print smoke scope and the 10-seed list. |
| K6 | 3 | Return code 0. Six refusal codes and seven deletion mutants are reported; all seven deletion lines end `FLAGGED`. |

The 18 outcomes are therefore 13 passes, two expected failures, and three expected operational failures. K2 and K3 count as matching reference replays, not scientific passes. K5 stops before any scientific verdict. `RESULTS.md` states this distinction correctly.

For U01, R01, K1, K5, and K6, sanitized stdout bytes and observed outcomes are identical across all three locked modes. The original protocol does not claim this parity for K2, K3, or K4, and neither do I. K5 and K6 stderr differences are consistent with warning handling and are outside the stdout parity definition.

As an additional read-only check, I compared each saved stdout file with the corresponding prior smoke recording in the pinned Cave checkout. All 18 pairs were byte-identical. This extra comparison is not required by the receipt protocol and is not a fresh target execution. Cave's recorded stderr includes timing-wrapper lines, while the POC captures direct process stderr; K5 also has sanitized paths. Those expected differences do not contradict any parity claim.

## Source and scope bindings

`SOURCE.json` exactly matches the locked public Cave repository, commit, suite root, Aletheia repository, pull request, commit, and POC lock digest. Its timestamp has the required UTC-second shape. The summary declares `N0`, `reference_replay`, `smoke_not_a_full_result`, and `real_data_readiness:BLOCKED`.

Every K command has the sole case argument `smoke`. K2, K3, and K4 are locked to plain mode only. No locked command invokes a model, network utility, shell helper, real-data reader, or paid service. AST inspection of the target `known_answer` and `src` modules found no network or model-provider imports. One unused target shell helper names credential environment variables only to unset them and deny network access; no locked case invokes it and it contains no credential value.

Cave's own `SMOKE_RESULTS.md` agrees with the stored outcomes. Its `AMENDMENTS_NEEDED.md` retains the K5 overflow blocker, incomplete mutation triage, unbuilt checks, and real-data hold. Nothing in this POC clears those gates. The target plan and POC both remain `N0` and make no live-model claim.

## Public hygiene

I scanned all 65 then-existing POC text files, including run outputs and earlier reviews. The checks covered local home-directory paths, prohibited attribution and private-name markers, private-key blocks, bearer tokens, credential assignments, and common token shapes.

Observed counts were zero for every prohibited category. A broader credential-word search found only the two benign prose statements in `PREREG.md` and `PROTOCOL.md` saying that public files contain no credentials and that the runner removes credential environment variables. No credential value was present or reproduced here.

The runner constructs a minimal environment rather than inheriting user credentials or Python paths. The run manifest contains only the 39 expected UTF-8 text files. This review itself uses placeholders rather than local absolute paths.

## Findings

### Blocking defects

None.

### Nonblocking integrity hardening: source timestamp is not digest-bound

`SOURCE.json` is schema-checked and its target, Aletheia, and lock fields are fully rebound to locked inputs. However, neither the receipt chain nor `SUMMARY.json` contains a digest of the complete `SOURCE.json`; `recorded_utc` is checked only for format. A later change to that timestamp alone would therefore not invalidate the current checker.

This does not overturn the verdict: the timestamp does not select a case, threshold, outcome, commit, or digest, and all decision-relevant source fields are bound. The source byte hash reported above is an independent review observation, not an existing chain anchor. A future protocol version could bind the complete source hash in the summary or terminal receipt. The present record was left unchanged.

### Scope observations, not defects

- This review verified stored evidence and prior recordings; it deliberately did not execute the expensive target cases again.
- The receipt protocol verifies locked process outcomes and markers, not general byte equality with Cave's older recordings. My additional stdout comparison passed for all 18 cases but is supplementary.
- Three-mode parity is limited to the five cases for which it was locked. K2, K3, and K4 do not gain three-mode coverage from Cave's separate historical recordings.
- Automated secret scans are bounded by their patterns and do not prove arbitrary prose safe. The manual scope and content inspection found no public-release blocker.

## Final ruling

The original evidence and its contradictions remain intact. The cancelled development runs and earlier parser failures are not represented as authoritative results. The authoritative `runs/run-001` record is internally consistent, independently recomputable, and consistent with the pinned Cave recording.

**APPROVE for the narrow tooling conclusion in `RESULTS.md`. No scientific validation, full-size result, real-data readiness, live-model claim, paid-run claim, or novelty upgrade follows.**

## Appendix A: complete independent auditor command

Run from `<POC>`. This read-only command does not import or call the POC evaluator.

```bash
python3 -I -B - <<'PY'
import collections, hashlib, json, re
from pathlib import Path

root=Path('.')
run=root/'runs/run-001'
def load(path):
    def pairs(items):
        out={}
        for k,v in items:
            if k in out: raise RuntimeError('duplicate key '+k)
            out[k]=v
        return out
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=pairs,
        parse_float=lambda x: (_ for _ in ()).throw(RuntimeError('float '+x)),
        parse_constant=lambda x: (_ for _ in ()).throw(RuntimeError('constant '+x)))
def canon(x):
    if isinstance(x,float): raise RuntimeError('float')
    return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def digest_obj(x): return hashlib.sha256(canon(x)).hexdigest()

lock=load(root/'LOCK.json'); cases=load(root/'cases.json')
locked_names=['PREREG.md','PROTOCOL.md','cases.json']+[str(p.relative_to(root)) for p in sorted((root/'evaluation').glob('*.py'))]
assert set(locked_names)==set(lock['files'])
assert all(sha(root/n)==lock['files'][n] for n in locked_names)
assert lock['cases_sha256']==sha(root/'cases.json')
assert lock['target_commit']==cases['target']['commit']
assert lock['aletheia_commit']==cases['aletheia']['commit']
lock_sha=sha(root/'LOCK.json')

source=load(run/'SOURCE.json')
assert set(source)=={'schema','target','aletheia','lock_sha256','recorded_utc'}
assert source['schema']=='warp-drive.cave-four-transformations.source.v1'
assert source['target']==cases['target'] and source['aletheia']==cases['aletheia']
assert source['lock_sha256']==lock_sha
assert re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z',source['recorded_utc'])

receipt_bytes=(run/'receipts.jsonl').read_bytes()
assert receipt_bytes.endswith(b'\n')
receipts=[json.loads(line,object_pairs_hook=lambda p:dict(p),parse_float=lambda x:(_ for _ in ()).throw(RuntimeError('float'))) for line in receipt_bytes.splitlines()]
case_by_id={c['id']:c for c in cases['cases']}
pairs=[(c['id'],m) for c in cases['cases'] for m in c['expected']]
assert len(receipts)==len(pairs)==18
previous=None
for seq,(r,pair) in enumerate(zip(receipts,pairs)):
    assert (r['case'],r['mode'])==pair and r['sequence']==seq and r['previous_sha256']==previous
    signed={k:v for k,v in r.items() if k!='receipt_sha256'}
    assert r['receipt_sha256']==digest_obj(signed)
    c=case_by_id[r['case']]; m=r['mode']; stem=r['case']+'-'+m
    assert r['command']==['<python>',*cases['modes'][m],'<target>/'+c['script'],*c['args']]
    assert (r['oracle'],r['timeout_seconds'],r['expected'])==(c['oracle'],c['timeout_seconds'],c['expected'][m])
    assert (r['target_commit'],r['lock_sha256'])==(cases['target']['commit'],lock_sha)
    assert (r['stdout_file'],r['stderr_file'])==(stem+'.stdout.txt',stem+'.stderr.txt')
    out=(run/r['stdout_file']).read_bytes(); err=(run/r['stderr_file']).read_bytes()
    assert hashlib.sha256(out).hexdigest()==r['stdout_sha256']
    assert hashlib.sha256(err).hexdigest()==r['stderr_sha256']
    text=out.decode('utf-8'); lines=text.splitlines(); rc=r['return_code']
    if c['kind']=='summary':
        summaries=[x for x in lines if x.startswith('SUMMARY ')]
        prefix='SUMMARY '+c['summary_id']+' SMOKE '
        match=re.fullmatch(re.escape(prefix)+r'(PASS|FAIL) \| .+',lines[-1]) if lines else None
        valid=(len(summaries)==1 and lines[-1]==summaries[0] and match is not None)
        verdict=match.group(1) if valid else None
        observed='pass' if verdict=='PASS' and rc==0 else 'fail' if verdict=='FAIL' and rc==1 else 'operational_failure'
    else:
        tail=[c['pass_marker'],'PASS'] if c['kind']=='units' else [c['pass_marker']]
        observed='pass' if rc==0 and lines[-len(tail):]==tail and lines.count(c['pass_marker'])==1 else 'operational_failure'
    if r['timed_out']: observed='operational_failure'
    assert observed==r['observed'] and r['matched']==(observed==r['expected'])
    assert isinstance(r['elapsed_ms'],int) and r['elapsed_ms']>=0
    previous=r['receipt_sha256']

counts=collections.Counter(r['observed'] for r in receipts)
parity=[]
for case in sorted(case_by_id):
    items=[r for r in receipts if r['case']==case]
    if len(items)>1:
        equal=all((run/x['stdout_file']).read_bytes()==(run/items[0]['stdout_file']).read_bytes() and x['observed']==items[0]['observed'] for x in items[1:])
        parity.append({'case':case,'modes':[x['mode'] for x in items],'stdout_and_outcome_equal':equal})
summary=load(run/'SUMMARY.json')
expected_summary={'schema':'warp-drive.cave-four-transformations.summary.v1','novelty':'N0','evidence_class':'reference_replay','scientific_size':'smoke_not_a_full_result','real_data_readiness':'BLOCKED','target_commit':cases['target']['commit'],'lock_sha256':lock_sha,'receipt_count':18,'outcome_counts':dict(sorted(counts.items())),'mismatches':[],'parity':parity,'status':'REFERENCE_REPLAY_COMPLETE','terminal_receipt_sha256':previous}
assert summary==expected_summary and all(p['stdout_and_outcome_equal'] for p in parity)
assert sha(run/'receipts.jsonl')=='f98227b4c1b8ad5e102a078950ed88a74733a964762b27150e570d889fe80573'
assert sha(run/'SUMMARY.json')=='6f0c9358e2ad257c2161d21a350f4b00b5d4b2af1f0ec51eff41d07bd74ca019'
assert lock_sha=='9f1c5cd103696d342b2b152de8058cde278e371d980526b5db6e3e08946f6466'
assert previous=='a613eafb93c4fc44867f20102a1dda393c596835a4455e3142023b155ee2c1d7'
manifest={'SOURCE.json','SUMMARY.json','receipts.jsonl'}|{f'{c}-{m}.{stream}.txt' for c,m in pairs for stream in ('stdout','stderr')}
entries=list(run.rglob('*'))
assert {p.name for p in entries}==manifest and len(entries)==39
assert not any(p.is_symlink() or p.is_dir() for p in entries)

# Direct content oracles, independent of the evaluator's classification helper.
for m in cases['modes']:
    assert (run/f'U01-{m}.stdout.txt').read_text().splitlines()[-2:]==['UNIT CHECKS: 336 checks, 0 failed','PASS']
    assert (run/f'R01-{m}.stdout.txt').read_text().splitlines()[-1]=='UNGUARDED: none'
    assert 'SUMMARY K1 SMOKE PASS | 7614 main checks, 0 failed; cases not representable 0; must-fail controls all flagged: yes' in (run/f'K1-{m}.stdout.txt').read_text()
    assert 'SUMMARY K6 SMOKE PASS | 6 refusal codes, 7 deletion mutants; each refusal fired on its must-fail input; every deletion flagged: yes' in (run/f'K6-{m}.stdout.txt').read_text()
    k6=(run/f'K6-{m}.stdout.txt').read_text().splitlines()
    mutants=[x for x in k6 if x.startswith('  without the refusal')]
    assert len(mutants)==7 and all(x.endswith(': FLAGGED') for x in mutants)
    assert len(set(re.findall(r'\((GATE_[A-Z]+)\)', '\n'.join(mutants))))==6
    k5=(run/f'K5-{m}.stdout.txt').read_text()
    assert 'SUMMARY ' not in k5 and 'SIZE SMOKE' in k5 and 'seeds: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9] of 10' in k5
assert 'SUMMARY K2 SMOKE FAIL | K2a flagged: False; K2b flagged: False; control flagged: False' in (run/'K2-plain.stdout.txt').read_text()
assert '4 of 10 reject; flag point 5 of 10' in (run/'K2-plain.stdout.txt').read_text()
assert 'SUMMARY K3 SMOKE FAIL | 1 gating cells below criterion; control flagged: True' in (run/'K3-plain.stdout.txt').read_text()
assert "('logistic', 'sub2', 3)" in (run/'K3-plain.stdout.txt').read_text()
assert 'SUMMARY K4 SMOKE PASS | A>B 9/10, A>C 10/10, control arrow 0 profile 0 (cap 1)' in (run/'K4-plain.stdout.txt').read_text()
assert 'blind spot (reported): arrow transfer rejects (p <= 0.01) in 0 of 20 seed-directions' in (run/'K4-plain.stdout.txt').read_text()
for m in ('plain','optimized','warnings'):
    err=(run/f'K5-{m}.stderr.txt').read_text()
    if m=='warnings': assert 'RuntimeWarning: overflow encountered in exp' in err
    else: assert 'GATE_MISSING: series has missing or non-finite values' in err

print(json.dumps({'independent_checks':'PASS','locked_files':len(locked_names),'lock_sha256':lock_sha,'receipts':len(receipts),'receipt_log_sha256':sha(run/'receipts.jsonl'),'summary_sha256':sha(run/'SUMMARY.json'),'terminal_receipt_sha256':previous,'source_sha256':sha(run/'SOURCE.json'),'manifest_files':len(entries),'outcome_counts':dict(sorted(counts.items())),'parity':parity,'k6_mutants_per_mode':7,'k6_refusal_codes_per_mode':6,'k5_summaries_per_mode':0},sort_keys=True))
PY
```
