# Evidence under research/ is a preserved record. Its archived test scripts and
# probes reproduce past runs and are not part of the repository test suite, so
# keep a root `pytest` run from collecting them. Run them as their own records
# describe.
collect_ignore_glob = ["*"]
