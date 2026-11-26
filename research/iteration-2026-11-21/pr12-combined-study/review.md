## Request changes: singleton composed certificates need equality, not only an upper bound

Reviewed head `10ae3b33402d9e5ef6f74cf9d8bf5d4c462cd931`. The committed studies and certificate regeneration reproduce, but an independent adversarial witness shows that the optional composed-certificate path can accept a false norm claim for one adapter.

### Reproduced soundness defect

`check_composed_norm_triangle_exact()` at `studies/expedition-gram-cert-upgrades/warp_drive_gram_cert_audit.py:738-752` checks `composed_sq <= n * sum(component_sq)`. It adds stricter triangle checks only when `n >= 2`. For `n == 1`, any nonnegative composed value between zero and the actual component value passes.

`verify_stack_hardened()` calls this check at `:1012-1016`. It separately verifies the composed certificate's digest, stack binding, and upper bounds, but those checks do not make an understated composed norm consistent with the singleton stack.

The preserved witness constructs:

- One valid component with scaled Frobenius and spectral-norm squares both equal to 16.
- A correctly digest-bound composed certificate for that same singleton stack, with both composed values equal to zero.

Observed result:

```text
{'n_adapters': 1, 'joint_bounds_checked': True, 'composed_bound_checked': False, 'gram_escape_used': False, 'composed_cert_verified': True, 'passed': True}
```

This is mathematically impossible for the represented singleton sum: the composed squared norm must equal the scaled component value, not merely be no greater than it. The result contradicts the verifier's composed-certificate soundness claim.

Please require exact equality for the singleton case and add adversarial regressions for understatement and overstatement. Overstatement is already rejected by the Cauchy-Schwarz upper bound in this witness class. Retain that behavior as an explicit control. Recheck the committed certificate and standalone digests after the repair.

Witness: `repro_single_adapter_composed_forgery.py`, SHA-256 `955c65543be697844e761a3b49dcc451aca191c77c4bfbf784d6aac2824e87b2`. The parent independently replayed it at the reviewed head. Output SHA-256 is `52cbac0a421a21092c6db6b3564956ccfed0afbffa44120f1ddf3d030482fdda`.

### Evidence that did reproduce

- Bridge and Gram standalone studies each passed in four isolated modes. Bridge stdout was byte-identical with SHA-256 `371495f0ef46ff9401d43300d008caa7e39486e6b562b707dcb7c486ea09524d`. Gram stdout was byte-identical with SHA-256 `192a1a4e1292c0153c4e3db37a7d633ae90ac9d7f59aabfeddc67bf12c90b4fa`.
- Bridge R5 passed 4 of 4 groups in all four modes. Gram R5 passed 11 tests in all four modes.
- Repository baseline ran 58 tests: 57 passed and 1 optional live-GGUF test skipped.
- Both live-anchored certificate canonical digests recomputed correctly, with no floating-point values in either certificate. Bridge: `9e3f9a74c86c9de0717a2814d480413989be6fed2a8b56a186fc61913cf78450`. Gram: `47509c47e05f94bc7efb53282130e3847843e1bc4fae5832654876debc21802f`.
- The preserved public graph recomputation records 294,912 neurons, 72,553 wires, zero backward wires, zero same-layer wires, and exact wire-buffer length. This is a static graph artifact, not live model behavior.

This review requests a local verifier repair. It does not dispute the reproduced numerical certificates, and it establishes no live weight-iteration result.
