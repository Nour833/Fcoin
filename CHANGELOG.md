# Changelog

## 2.3.0 — 2026-06-22

- Fixed the value-edit wizard asking for an unexplained path after backup selection.
- Added guided detection of structurally valid writable value blocks from the selected backup.
- Added automatic exact-UID profile creation inside the selected session.
- Added explicit confirmation before treating equal-value blocks as mirrors.
- Added clear existing-profile discovery without re-requesting the card backup.
- Audited and clarified all intentional multi-file prompts.
- Added a live NFC tool, reader, card-presence, and UID status rail to every menu.
- Added automatic menu refresh while connection or card state changes.
- Added an operation lock that stops and drains monitoring before any card operation.
- Disabled all hardware probing while an external write or recovery is pending.

## 2.2.0 — 2026-06-22

- Added direct live-card inspection with `fcoin inspect --reader`.
- Live inspection now performs two matching reads and automatically saves an immutable backup before analysis.
- Added `fcoin inspect --session <id>` for inspecting saved FCOIN backups.
- Added an interactive Inspect source menu for live cards, session backups, and disk files.
- Added live-reader key dictionary, probe-count, and timeout controls.
- Added session ID and backup-path details to inspection output and JSON.

## 2.1.0 — 2026-06-22

- Added a colorful full-screen control center for no-argument `fcoin`.
- Added arrow-key, `j`/`k`, number-key, back, escape, and quit navigation.
- Added guided workflows for every major command category.
- Added compatible-file discovery and secure-session selection.
- Made incomplete terminal commands open their workflow wizard.
- Added friendly `--inspect`, `-inspect`, `--doctor`, and related aliases.
- Preserved direct command and JSON behavior for scripts and automation.

## 2.0.0 — 2026-06-22

- Replaced the monolithic prototype with an installable Python package.
- Added a dependency-free styled CLI and JSON automation output.
- Added Mini, Classic 1K, and Classic 4K geometry.
- Added exact value-block and access-condition validation.
- Added immutable backups with optional two-read verification.
- Added explainable detectors, cross-dump inference, and evidence questions.
- Added block, byte, and bit comparison.
- Added MFD and MCT text-dump conversion.
- Added HTML and JSON reports.
- Added UID-bound laboratory profiles and exact decimal value planning.
- Added integrity-hashed plans, durable hash-chained journals, verification, and recovery.
- Removed automatic `sudo apt` package installation.
- Added security, contribution, architecture, and profile documentation.
- Added comprehensive synthetic tests and CI.
