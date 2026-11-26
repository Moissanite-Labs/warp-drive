# Harness development failures

These failures occurred while testing the POC harness. No Cave target case had run, no result receipt existed, and no scientific threshold changed.

1. The first isolated lock command could not import the runner. Python isolated mode does not put the script directory on the import path. The three POC entry points now add their own directory explicitly.
2. A shell loop passed a group of Python flags as one argument. The three test modes now use separate explicit commands. This was a driver command error, not a harness result.
3. The first control run exposed two runner defects. The JSON float callback returned the decimal token as a string, so a forbidden float could enter a receipt. It now rejects every float token. Path redaction used only resolved paths, so an unresolved path through a symbolic link could survive. It now replaces both raw and resolved forms.
4. The same control run exposed a test defect. The no-bare-assert scan iterated over locked Markdown files as well as Python files. It now parses only Python sources.

The corrected controls must pass in all three modes before the source lock is regenerated and the target replay starts. These notes record tooling development only. They are not target evidence.
