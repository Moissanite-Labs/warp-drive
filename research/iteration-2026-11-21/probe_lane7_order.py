import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('utf-8')


def sha(value):
    return hashlib.sha256(canonical(value)).hexdigest()


if len(sys.argv) != 2:
    raise SystemExit('usage: probe.py /path/to/lane7/verify.py')
spec = importlib.util.spec_from_file_location('lane7_verify', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
config = {'rank': 8, 'target_layer': 'last'}
raw = [
    {'event': 'candidate_proposed', 'candidate_id': 'order-control', 'config': config, 'config_digest': sha(config)},
    {'event': 'evaluated', 'candidate_id': 'order-control', 'measurements': {'task_top1': 1}},
    {'event': 'candidate_digest_recorded', 'candidate_id': 'order-control', 'config_digest': sha(config)},
]
entries = []
prev = '0' * 64
for seq, event in enumerate(raw, 1):
    entry = dict(event, seq=seq, prev_sha256=prev)
    entry['entry_sha256'] = sha(entry)
    prev = entry['entry_sha256']
    entries.append(entry)
log = Path('/tmp/lane7-independent-order.jsonl')
log.write_bytes(b''.join(canonical(entry) + b'\n' for entry in entries))
results = {
    'events_independently_hashed': [entry['event'] for entry in entries],
    'receipt_log': module.check_receipt_log(log)[0],
    'config_digests': module.check_config_digests(log)[0],
}
if results['receipt_log']['verdict'] != 'VERIFIED':
    raise RuntimeError('independently constructed hash chain rejected')
if results['config_digests']['verdict'] != 'VERIFIED':
    raise RuntimeError('suspected fail-open path not reproduced')
print(json.dumps(results, indent=2))
