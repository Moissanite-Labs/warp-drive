# Aletheia bounded trial receipt — spectral-inertia

Date: 2026-11-21 America/Chicago
Verdict: N0 / negative evidence. No counterexample, soundness repair, or N1 finding survived checking.

## Exact sources

- spectral-inertia main: 8394da989912bbc3a0e8702124aeec1d05b4801f
- Sole open PR at inspection: #2, head ef1a77db5924aa958b45c8affbb2424dcb1d9e2b, base 8394da989912bbc3a0e8702124aeec1d05b4801f. PR #2 alters only lean/README.md and lean/SpectralInertia/Basic.lean; git diff confirms spectral_inertia/, tests/, and run_all.py are unchanged. Lean compilation was not rerun in this trial.
- Independent cross-oracle: bareiss_gram_gate.py at merged commit 38a7072f8d23fe865b4d48d1da285a6db4fc14d1. The supplied worktree file is byte-identical to the blob at that commit. SHA-256: 5794996c272b5cfca38d7599895303d90ea43e2372524290122425a5ec615772.

## Seam and commands

Executable seam: real-integer/rational boundary of the PLDL producer + dual-oracle verifier, cross-checked against the separately implemented Bareiss symmetric inertia routine. This was selected rather than re-deriving theory; the only open PR does not touch this code.

Clone/fetch:
  git clone --filter=blob:none https://github.com/Foundation-0/spectral-inertia.git /tmp/aletheia-spectral-inertia-20261121-1524/repo
  git -C /tmp/aletheia-spectral-inertia-20261121-1524/repo fetch origin refs/pull/2/head:refs/remotes/origin/pr/2

Upstream baseline from repo root:
  python3 -I -B run_all.py
  python3 -I -O -B run_all.py

Both passed: 16/16 unit tests and 41/41 mutants killed; all listed Track A/B/Bloch/truss benchmark statuses matched the repository summary.

Probe from /tmp/aletheia-spectral-inertia-20261121-1524:
  python3 -I -B probe_real_integer_boundary.py repo /path/to/bareiss_gram_gate.py
  python3 -I -O -B probe_real_integer_boundary.py repo /path/to/bareiss_gram_gate.py
  python3 -I -B -W error probe_real_integer_boundary.py repo /path/to/bareiss_gram_gate.py
  python3 -I -O -B -W error probe_real_integer_boundary.py repo /path/to/bareiss_gram_gate.py

All four runs exited 0 with byte-identical JSON. Exact results:
- 860 matrices checked with zero disagreements: every real symmetric 2x2 matrix with entries in {-2,-1,0,1,2} (125), every real symmetric 3x3 matrix with entries in {-1,0,1} (729), and 6 targeted Fraction matrices after positive integer denominator clearing.
- Coverage: 230 singular; 32 zero-diagonal; 82 requiring producer 2x2 pivots. All inertia histogram entries agreed among Oracle 1, Descartes, Sturm, and Bareiss.
- Maximum rational clearing scale: 30.
- Executed probe SHA-256: 0560d6374838b5e276d3380c4626873845cd3e7fedabdb7d87f2e1f078df74ab.
- Probe output SHA-256: ffd4ca1c745912a33e4f4dd123d4fbedfe9e5821ea6ef0299493c9ac966850ef.

Publication portability edit: the original executed source embedded a host-specific absolute oracle path. The published source replaces only the two source-path constants with required command-line arguments. The original executed hash above remains the hash of the trial witness. No matrix, oracle, assertion, result, or runtime-mode logic changed. This edit was made for public repository hygiene, not to change a trial outcome. The manifest hashes the portable published source separately.

Published source SHA-256: a0198b21e653b04f67776ccf117d7c9207f3787f20248d1a25b7a8edd97e9b5b. One explicit portability replay using the new arguments exited 0 and matched `probe-normal.json` byte-for-byte, including output SHA-256 `ffd4ca1c745912a33e4f4dd123d4fbedfe9e5821ea6ef0299493c9ac966850ef`. This replay verifies only the path edit; it is not a new scientific finding or a replacement for the original four-mode execution.

## Minimal replay witness and negative control

No failing witness exists in this trial. The minimal producer/optimizer-isolated successful replay witness is:

  M = [[0,1,0],
       [1,0,0],
       [0,0,0]]

Exact inertia: (n_+, n_-, n_0) = (1,1,1). The explicit payload P=[0,1,2], L=I, D=M bypasses produce_pldl_certificate and all search/optimization. Oracle 1, Descartes, Sturm, and Bareiss independently returned (1,1,1).

The must-fail control kept M, P, L, and D unchanged but changed the claimed inertia to [2,1,0]. It was rejected with INERTIA_CLAIM_MISMATCH in every runtime mode.

## Independence and scope limits

Bareiss supports real integer symmetric matrices. Rational inputs were multiplied by a positive common integer denominator, which preserves inertia exactly. It supplies implementation diversity against Oracle 2 but does not extend this evidence to general complex Q(i), continuous box certification, higher-moment optimizer soundness, or Lean kernel verification. Bareiss and repository Oracle 1 both use congruence/Sylvester-style mathematics, so agreement is not independence of the underlying theorem class; Descartes and Sturm additionally share the repository's computed characteristic polynomial. All checks were executed by one agent in one process family. This finite exhaustive boundary is evidence only, not a new universal theorem or novelty claim. No broad literature novelty claim is made.

No external writes, branches, pushes, issues, comments, installs, payments, or credential use occurred. All created artifacts are under /tmp/aletheia-spectral-inertia-20261121-1524; the upstream and cross-oracle source files were not modified.
