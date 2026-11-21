# Golden fixtures (generated, not hand-written)

Produced by a fake-runtime run of the lane-5 controller at head
c526b8d against the frozen contract at f9c9acc (see the audit log for
the generator command). The run used fake compiler, runtime, and
lifecycle adapters, so these files prove control flow and receipt
shape only, never adapted-model evidence.

Known property of the fixture: the `evaluated` entry in
`receipts.jsonl` carries a NaN rollback placeholder, so the log is
not strict JSON. The lane-7 verifier flags exactly that.

Verdict of the generating run: ACCEPT
