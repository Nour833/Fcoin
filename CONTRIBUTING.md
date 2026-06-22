# Contributing

## Principles

- Protocol facts must be distinguishable from heuristic interpretations.
- New detectors must include evidence, confidence, and tests.
- Write-related changes must preserve immutable snapshots, exact preconditions, and post-write verification.
- Never add automatic privilege escalation, silent network access, or secret logging.
- Tests must use synthetic fixtures rather than real card dumps.

## Development setup

```bash
python3 -m pip install -e .
PYTHONPATH=src python3 -m unittest discover -v
python3 -m compileall -q src tests fcoin.py
```

## Pull requests

Include:

- The user-visible behavior being changed.
- Safety and compatibility implications.
- Tests for success and failure paths.
- Documentation updates when commands or formats change.

Do not commit MFD files, key dictionaries, session data, generated reports, or real UIDs.
