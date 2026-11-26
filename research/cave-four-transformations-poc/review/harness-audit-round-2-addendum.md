# Addendum: actual U01 output invalidated round 2 for execution

The round-two harness re-review was internally consistent with its synthetic fixtures. Those fixtures did not reproduce the real U01 output's final line. A later target-shape check therefore superseded the review's readiness ruling for execution.

The first attempted run under lock `b68d24271b06a53a2ba5787b8744b984d28eaca8b231128b14fb95b7018c7ffd` stopped after one receipt. U01-plain printed `UNIT CHECKS: 336 checks, 0 failed`, then a separate final line `PASS`, and returned zero. The parser incorrectly required the count marker itself to be terminal, so it classified this genuine target pass as an operational failure. This was a false reject caused by the POC parser, not a Cave failure. No K case ran, and no summary exists.

The run directory is preserved as `development-run-002-cancelled`. It is not a scientific result. Its actual U01 output is the regression fixture for the next independent review.

The parser now requires the exact U01 tail `[count marker, PASS]`. R01 still requires its unique `UNGUARDED: none` marker as the final line. Duplicate markers, suffixes, trailing failure text, and inconsistent return codes remain operational failures. The runner and verifier now redact the Python installation prefix, and the public scan covers its framework-path family.

The replacement lock is `9f1c5cd103696d342b2b152de8058cde278e371d980526b5db6e3e08946f6466`. All 19 controls passed in each of the three Python modes. A separate independent delta review must approve that exact lock and the actual saved U01 shape before another replay.

This sequence preserves the development failure and the limits of synthetic review. It does not alter any Cave target file or Cave test expectation. Novelty remains `N0`, and real-data readiness remains `BLOCKED`.
