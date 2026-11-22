#!/usr/bin/env python3
"""Zero-shared-code audit of the PR13 result mutation and harness receipts."""
import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path('/tmp/tokenpage-pr13-a694232/studies/expedition-proper-kl-audit')
MUTANT = Path('/tmp/tokenpage-pr13-mutation/studies/expedition-proper-kl-audit')
TRIAL = Path('/tmp/tokenpage-harness-trial-20261121')
FIELDS = {'title': 12, 'priority': 4, 'scope': 6, 'criteria': 5, 'dependency': 2}


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def empirical_kl(rows):
    grouped = defaultdict(list)
    for row in rows:
        grouped[row['field']].append(row)
    total = 0.0
    for field in FIELDS:
        observations = grouped[field]
        check(len(observations) == 24, f'{field}: wrong sample size')
        empirical = Counter(int(row['gold']) for row in observations)
        n = len(observations)
        entropy = -sum((count / n) * math.log2(count / n) for count in empirical.values())
        cross_entropy = -sum(math.log2(max(float(row['p_gold']), 1e-12)) for row in observations) / n
        total += entropy - cross_entropy
    return total


raw_path = ROOT / 'data/tokenpage_pr5/raw_qa_qwen1.5b.jsonl'
rows = [json.loads(line) for line in raw_path.read_text(encoding='utf-8').splitlines() if line]
check(hashlib.sha256(raw_path.read_bytes()).hexdigest() == '8cc8f1ce33be37a2d2ece4b5dab0722db5772460478551bb2007d319b0508334', 'raw QA hash mismatch')
check(hashlib.sha256((MUTANT / 'data/tokenpage_pr5/raw_qa_qwen1.5b.jsonl').read_bytes()).hexdigest() == '8cc8f1ce33be37a2d2ece4b5dab0722db5772460478551bb2007d319b0508334', 'mutation touched raw QA')
summary = {}
for legend in (False, True):
    cell = [row for row in rows if 0 <= row['msg'] < 24 and row['fmt'] == 'glyph_g1' and bool(row['legend']) is legend]
    check(len(cell) == 120, f'legend={legend}: wrong cell size')
    summary[legend] = empirical_kl(cell)
recomputed_delta = round(round(summary[True], 4) - round(summary[False], 4), 4)

clean_artifact = json.loads((ROOT / 'probe_s2_nullmodem_tokenpage_results.json').read_text(encoding='utf-8'))
mutant_artifact = json.loads((MUTANT / 'probe_s2_nullmodem_tokenpage_results.json').read_text(encoding='utf-8'))
key_path = ('part1_live_tokenpage_pr5_audit', 'issue9_proper_kl_floor_inversion', 'g1_legend_delta_proper_KL_emp_bits')
clean_value = clean_artifact[key_path[0]][key_path[1]][key_path[2]]
mutant_value = mutant_artifact[key_path[0]][key_path[1]][key_path[2]]
check(clean_value == recomputed_delta == 1.767, 'clean artifact does not match independent recomputation')
check(mutant_value == 9999.0 and mutant_value != recomputed_delta, 'mutation is not a certified numerical contradiction')

for study_root in (ROOT, MUTANT):
    check(not (study_root / 'measure.py').exists(), 'audit assumptions changed: measure.py now exists')
    check(not (study_root / 'requirements.txt').exists(), 'audit assumptions changed: requirements.txt now exists')
for receipt in ('clean-harness', 'mutated-harness'):
    check((TRIAL / f'{receipt}.status').read_text().strip() == '0', f'{receipt}: expected exit zero')
    log = (TRIAL / f'{receipt}.log').read_text()
    check('checked 0 studies' in log, f'{receipt}: missing zero-study evidence')
    check('skip studies/expedition-proper-kl-audit' in log, f'{receipt}: missing skip evidence')
check((TRIAL / 'named-harness.status').read_text().strip() == '1', 'named diagnostic did not fail loudly')
for receipt in ('research-run1', 'research-run2'):
    check((TRIAL / f'{receipt}.status').read_text().strip() == '0', f'{receipt}: research failed')
    check((TRIAL / f'{receipt}.diff.status').read_text().strip() == '0', f'{receipt}: research drifted')
    digest = (TRIAL / f'{receipt}.sha256').read_text().split()[0]
    check(digest == 'b0cba027918e623b6f1169499eb49693aa47bede08c0c58411542bd91c9408f8', f'{receipt}: digest mismatch')

output = {
    'verdict': 'FALSIFIED',
    'selected_claim': 'no-argument study harness certifies every added study and detects committed-result drift',
    'checked_studies_clean_and_mutated': 0,
    'clean_and_mutated_harness_exit': 0,
    'named_study_exit': 1,
    'independently_recomputed_g1_legend_delta': recomputed_delta,
    'unrounded_unfloored_empirical_kl': {'no_legend': summary[False], 'with_legend': summary[True]},
    'clean_artifact_delta': clean_value,
    'mutated_artifact_delta': mutant_value,
    'mutation_is_numerically_false': True,
    'research_replay_digests': ['b0cba027918e623b6f1169499eb49693aa47bede08c0c58411542bd91c9408f8'] * 2,
    'research_control_verdict': 'VERIFIED',
}
text = json.dumps(output, indent=2, sort_keys=True) + '\n'
(TRIAL / 'independent_audit.json').write_text(text, encoding='utf-8')
print(text, end='')
print('independent_audit_sha256=' + hashlib.sha256(text.encode('utf-8')).hexdigest())
