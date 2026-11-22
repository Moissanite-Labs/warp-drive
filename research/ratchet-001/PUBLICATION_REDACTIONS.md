# Ratchet 001 publication redactions

This receipt applies only to the public publication closure on branch `iteration/2026-11-22-ratchet-001-public`. It does not describe a new experiment, a changed verdict, or a candidate adaptation.

## Original local closure

- Commit: `ee465f5261e108bed6572baf35e7000cb71846ae`.
- Git tree: `a3905872a27a554dee133bdcd625dcc1e7666186`.
- Parent: `dc4c5f9d07e61cd60e60cd8f2c6d41b4fa8cf677`.
- `POST_BLIND_REPRODUCTIONS.json` SHA-256: `0c205d23cd907d78d5aba1416d40df62170d0fc0280aa835ccdcf9d4680f74ae`.
- `RESULT.md` SHA-256: `c48a1ee2247c8b2f3652002b9ff0da3ea00edaac3968aab345c0e1951ffc767c`.
- `POST_BLIND_REVIEW.md` SHA-256: `0101c86f626993f15096f82d8aca5bf91e5c87daae0fd3fdbac545deb1e62dcd`. The file is unchanged in the public closure.

The original local commit is not an ancestor of the public branch because its traceback JSON embeds absolute local filesystem paths. Publishing that ancestry would violate the repository's public-hygiene rule.

## Public closure

- `POST_BLIND_REPRODUCTIONS.json` SHA-256: `268a73f5a30ae88a37222dcd2def16add055aa7154468170a153ba8bc7c8979e`.
- `RESULT.md` SHA-256: `d6b289c7c6398d292622fe52252c32a6ba715fcf30045adc973ac6521af331ab`.

The only reproduction-data change replaces twenty occurrences of the local ratchet directory prefix with `<workspace>/research/ratchet-001/`. Commands, case identifiers, return codes, stdout, exception types, exception messages, source line numbers, and all scientific observations remain unchanged. The JSON parses after redaction. `RESULT.md` now discloses that redaction. Its result counts and dispositions are unchanged.

The evaluation lock, corpus, candidate copy, requests, observations, chained receipts, summary, setup-failure records, blind review, and N0 verdict were not changed. Evaluation tree SHA-256 remains `95f8f2a374e2ef5253be3b3e3b3c489b0238d0451ddd190f935bc235671b00bf`. Terminal receipt SHA-256 remains `4f046fbfc2f9a1855c15226d762a09e831e4ab86ea758e2cd0b6a5871078391f`. No baseline or blind-review execution was repeated.
