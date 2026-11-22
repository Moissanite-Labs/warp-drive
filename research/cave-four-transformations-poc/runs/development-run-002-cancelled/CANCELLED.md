# Cancelled development run

The parent stopped this run after U01-plain was classified as an operational failure. The target actually printed 336 passing checks and return code zero. The replay parser incorrectly required the unit count marker to be the last line, but the target prints a separate final `PASS` line.

Only one receipt completed. No K case ran. No summary exists. This is a harness development artifact, not a target failure or POC result. The parser now requires the target's exact two-line closing shape. Redaction also covers the Python installation prefix used in tracebacks.
