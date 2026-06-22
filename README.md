<div align="center">

<pre>
███████╗ ██████╗ ██████╗ ██╗███╗   ██╗
██╔════╝██╔════╝██╔═══██╗██║████╗  ██║
█████╗  ██║     ██║   ██║██║██╔██╗ ██║
██╔══╝  ██║     ██║   ██║██║██║╚██╗██║
██║     ╚██████╗╚██████╔╝██║██║ ╚████║
╚═╝      ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝
</pre>

### Local-first MIFARE Classic forensics, backup, and guarded recovery

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-45E1FF?style=flat-square&logo=python&logoColor=0B0F14)](https://python.org)
[![Zero runtime dependencies](https://img.shields.io/badge/runtime_dependencies-0-7DFFB2?style=flat-square)](#installation)
[![Tests](https://img.shields.io/badge/tests-21_passing-7DFFB2?style=flat-square)](#development)
[![License: MIT](https://img.shields.io/badge/license-MIT-FFCF70?style=flat-square)](LICENSE)

**Acquire. Validate. Understand. Plan. Record. Verify. Recover.**

</div>

---

FCOIN is an offline-first toolkit for examining and safely maintaining MIFARE Classic cards that you own or are explicitly authorized to test. It replaces the original single-script prototype with a structured package, deterministic analysis engine, immutable snapshots, exact access-condition decoding, surgical change plans, tamper-evident write journals, post-write verification, and recovery planning.

FCOIN does not silently write cards, install packages with `sudo`, upload dumps, or treat heuristic guesses as facts.

## What changed in 2.0

| Area | Capability |
|---|---|
| Backup | Two-read hardware acquisition, immutable snapshots, SHA-256 identity, `0600` files |
| Protocol | Mini, Classic 1K, and Classic 4K geometry |
| Integrity | Exact value-block redundancy, BCC indication, all access-bit complements |
| Analysis | Value blocks, text, UTF-16, timestamps, duplicate blocks, entropy, CRC candidates |
| Intelligence | Cross-dump inference, controlled comparisons, evidence-backed questions |
| Editing | UID-bound owned-lab profiles, exact decimal math, mirror-aware surgical plans |
| Transactions | Durable hash-chained journal written before external block writes |
| Verification | Target-byte verification plus detection of every collateral block change |
| Recovery | Restoration plans generated from the immutable trusted snapshot |
| Reporting | Styled terminal, JSON output, self-contained HTML reports |
| Formats | Binary MFD and Mifare Classic Tool text-dump conversion |
| Operations | Inventory, history, reader diagnostics, automation-friendly JSON |

## Safety boundary

FCOIN is intended for:

- Backing up cards you own.
- Recovering owned cards from accidental data-block corruption.
- Laboratory cards and synthetic fixtures.
- Authorized security research and format reverse engineering.
- Comparing known-before and known-after states from controlled experiments.

Writable value profiles must:

- Set `lab_only` to `true`.
- Bind to an exact UID prefix.
- Explicitly list writable fields and blocks.
- Define permitted minimum and maximum values.
- Receive the exact authorization phrase required by the CLI.

FCOIN always refuses automatic changes to manufacturer block 0 and sector trailers. It does not offer unrestricted third-party payment, transit, access-control, or stored-value alteration.

## The workflow

```text
             ┌─────────────┐
             │  ACQUIRE ×2 │  Two reads must match
             └──────┬──────┘
                    ▼
          ┌───────────────────┐
          │ IMMUTABLE SNAPSHOT│  SHA-256 + 0600 permissions
          └─────────┬─────────┘
                    ▼
       ┌─────────────────────────┐
       │ VALIDATE · INSPECT · DIFF│  Deterministic evidence
       └────────────┬────────────┘
                    ▼
       ┌─────────────────────────┐
       │ UID-BOUND CHANGE PLAN    │  Exact blocks and preconditions
       └────────────┬────────────┘
                    ▼
       ┌─────────────────────────┐
       │ DURABLE WRITE JOURNAL    │  Pending event persisted first
       └────────────┬────────────┘
                    ▼
       ┌─────────────────────────┐
       │ EXTERNAL BLOCK-WISE WRITE│  MCT or another authorized writer
       └────────────┬────────────┘
                    ▼
       ┌─────────────────────────┐
       │ READ ×2 · VERIFY ALL     │  Target + collateral comparison
       └───────┬─────────┬───────┘
               │ pass    │ fail
               ▼         ▼
          VERIFIED    RECOVERY PLAN
```

## Installation

FCOIN itself has no third-party Python runtime dependencies.

```bash
git clone https://github.com/Nour833/Fcoin.git
cd Fcoin
python3 -m pip install -e .
fcoin --help
```

It can also run directly from a checkout:

```bash
./fcoin.py
```

Hardware acquisition is optional. On Linux, install these through your operating-system package manager when needed:

- `mfoc` for authorized MIFARE Classic acquisition.
- `libnfc` utilities for `nfc-list` diagnostics.

FCOIN reports missing tools but never invokes `sudo` or changes the system.

## Quick start

### 1. Diagnose the reader

```bash
fcoin doctor
```

### 2. Create an immutable backup

Acquire twice with `mfoc`; the snapshot is accepted only when both reads match:

```bash
fcoin backup --reader
```

Use an optional, user-managed key dictionary:

```bash
fcoin backup --reader --keys ~/.config/fcoin/owned-lab.keys
```

Import an existing dump:

```bash
fcoin backup --from-dump card.mfd
```

Require two independently acquired imports to match:

```bash
fcoin backup \
  --from-dump read-1.mfd \
  --confirmation read-2.mfd
```

Analysis can use a single imported dump. Any writable plan requires a session backed by two identical independent reads.

Snapshots are stored under:

```text
~/.local/share/fcoin/sessions/<timestamp>-<uid>/
```

Override that location with `FCOIN_HOME` or `--home`.

### 3. Inspect and validate

```bash
fcoin validate card.mfd
fcoin inspect card.mfd
fcoin inspect card.mfd --all
fcoin inspect card.mfd --json
```

The analyzer reports protocol facts and candidates separately. A structurally valid value block is a fact; calling that value a balance requires a trusted profile or controlled evidence.

### 4. Compare controlled states

```bash
fcoin compare before.mfd after.mfd
fcoin compare before.mfd after.mfd --json
```

The diff includes:

- Changed blocks and sectors.
- Exact changed byte offsets.
- Number of changed bits.
- Before and after hex.
- Value-block interpretation when both states are structurally valid.

### 5. Infer structure from multiple observations

```bash
fcoin infer baseline.mfd event-1.mfd event-2.mfd \
  --output inference.json
```

All samples must use the same card geometry and UID prefix. FCOIN identifies valid value blocks across every sample and records which values changed.

### 6. Ask evidence-backed questions

```bash
fcoin ask card.mfd "what value blocks were found?"
fcoin ask card.mfd "is anything corrupt?"
fcoin ask card.mfd "show possible timestamps"
```

This assistant is deterministic, offline, and does not send card data anywhere.

### 7. Generate reports

```bash
fcoin report card.mfd --format html --output report.html
fcoin report card.mfd --format json --output report.json
```

The HTML report is self-contained and can be archived with a case or laboratory notebook.

## MCT conversion

Convert a complete binary MFD dump to Mifare Classic Tool text format:

```bash
fcoin convert card.mfd --from mfd --to mct --output card.mct
```

Convert a complete MCT text dump back to binary:

```bash
fcoin convert card.mct --from mct --to mfd --output card.mfd
```

Incomplete sector maps are rejected because they cannot serve as trusted recovery snapshots.

## Guarded value editing for owned laboratory cards

FCOIN does not edit a value because a heuristic merely “looks like a wallet.” A writable operation requires a reviewed profile bound to the exact owned card.

### 1. Find structural candidates

```bash
fcoin inspect owned-lab.mfd
fcoin infer lab-before.mfd lab-after-controlled-event.mfd
```

### 2. Create a profile template

```bash
fcoin profile-init owned-lab.mfd \
  --block 4 \
  --mirror 5 \
  --output owned-lab.profile.json
```

Review the generated file:

```json
{
  "name": "owned-lab-card",
  "description": "UID-bound profile for an owned laboratory card.",
  "lab_only": true,
  "allowed_uids": ["DEADBEEF"],
  "fields": [
    {
      "name": "test_value",
      "type": "value_block",
      "block": 4,
      "mirrors": [5],
      "scale": 100,
      "unit": "test credits",
      "minimum": "0.00",
      "maximum": "100.00",
      "writable": true
    }
  ]
}
```

### 3. Create a surgical plan

Find the session ID:

```bash
fcoin history
```

Create the plan:

```bash
fcoin plan-value \
  --session 20260622T120000.000000Z-DEADBEEF \
  --profile owned-lab.profile.json \
  --field test_value \
  --value 50.00 \
  --authorize "I OWN THIS LAB CARD"
```

Before accepting the plan, FCOIN verifies:

- The profile UID exactly matches the snapshot.
- Every primary and mirror block is a complete valid MIFARE value block.
- All mirror values agree.
- Access-condition redundancy is valid.
- The block is not write-prohibited.
- The requested decimal is exact at the configured scale.
- The signed 32-bit encoded value is in range.
- The value is inside profile bounds.
- The encoded address bytes are preserved.
- No manufacturer block or sector trailer is targeted.

### 4. Preview an offline result

```bash
fcoin apply-plan \
  ~/.local/share/fcoin/sessions/<session>/before.mfd \
  ~/.local/share/fcoin/sessions/<session>/value-plan.json \
  --output preview.mfd

fcoin compare \
  ~/.local/share/fcoin/sessions/<session>/before.mfd \
  preview.mfd
```

Only planned blocks may differ.

### 5. Prepare the write transaction

```bash
fcoin prepare-write \
  --session <session> \
  --plan ~/.local/share/fcoin/sessions/<session>/value-plan.json
```

This durably creates:

```text
write-plan.json          Integrity-hashed plan
intended.mfd             Exact expected complete image
write-instructions.json  Minimal block/payload list
journal.jsonl            Append-only hash-chained event log
```

Each block is recorded as `pending` before any external write occurs. Use MCT or another authorized block-wise tool to write only those listed data blocks.

### 6. Verify after writing

Read the card twice independently and provide both matching acquisitions:

```bash
fcoin verify-write \
  --session <session> \
  --observed after-1.mfd \
  --confirmation after-2.mfd
```

Or acquire two matching post-write reads:

```bash
fcoin verify-write --session <session> --reader
```

Verification fails if:

- The UID differs.
- Any target block differs from the plan.
- Any unrelated block changed.
- The final complete image differs from `intended.mfd`.
- The journal hash chain is damaged.

## Recovery after interruption or corruption

If verification fails, acquire the current card and generate a restoration plan:

```bash
fcoin recover \
  --session <session> \
  --current current-card.mfd \
  --authorize "RESTORE MY OWN CARD"
```

The recovery plan restores exact data-block bytes from `before.mfd`. FCOIN refuses automatic recovery when manufacturer block 0 or a sector trailer differs, because changing keys or access conditions requires a separate specialist procedure.

Apply and inspect the recovery plan offline:

```bash
fcoin apply-plan \
  current-card.mfd \
  ~/.local/share/fcoin/sessions/<session>/recovery-plan.json \
  --output recovery-preview.mfd

fcoin compare current-card.mfd recovery-preview.mfd
```

Then use the generated block payloads with an authorized block-wise writer and verify again.

## Transaction journal

Display and cryptographically verify the event chain:

```bash
fcoin journal --session <session>
```

Typical events:

```text
transaction_prepared
block_pending
block_pending
block_verified
block_verified
transaction_verified
```

Failed sessions retain the observed image, block-level failure events, collateral-change evidence, and recovery-plan reference.

## Session layout

```text
sessions/<timestamp>-<uid>/
├── metadata.json
├── before.mfd
├── confirmation.mfd
├── acquisition.log
├── value-plan.json
├── write-plan.json
├── intended.mfd
├── write-instructions.json
├── journal.jsonl
├── after.mfd
└── recovery-plan.json
```

Sensitive artifacts use mode `0600`; session directories use `0700`. Dumps, keys, sessions, reports, and plans are ignored by Git.

## Command reference

| Command | Purpose |
|---|---|
| `doctor` | Check `mfoc`, libnfc tools, and reader visibility |
| `backup` | Create an immutable imported or double-read snapshot |
| `validate` | Validate geometry, dump size, BCC indication, and access bits |
| `inspect` | Run explainable deterministic detectors |
| `compare` | Produce a block-, byte-, and bit-level diff |
| `infer` | Correlate structural value blocks across controlled samples |
| `ask` | Query deterministic analysis evidence |
| `report` | Create JSON or self-contained HTML reports |
| `convert` | Convert complete MFD and MCT dumps |
| `inventory` | Index dump files recursively or non-recursively |
| `history` | List snapshot and write-session state |
| `profile-init` | Create an exact-UID owned-lab profile template |
| `plan-value` | Build an integrity-hashed surgical value plan |
| `apply-plan` | Apply and verify a plan against an offline image |
| `prepare-write` | Persist intended state, payloads, and pending journal events |
| `verify-write` | Verify target blocks and detect collateral changes |
| `recover` | Generate restoration operations from the immutable snapshot |
| `journal` | Verify and display the transaction hash chain |

Every analysis-oriented command supports plain terminal output or JSON where appropriate. Set `NO_COLOR=1` or use `--no-color` for non-ANSI output.

## Architecture

```text
src/fcoin/
├── geometry.py       Mini / 1K / 4K memory mapping
├── access.py         Access-bit and permission decoding
├── value.py          Exact signed value-block codec
├── dump.py           Validated immutable card images
├── acquisition.py    mfoc and libnfc diagnostics adapters
├── analysis.py       Explainable deterministic detectors
├── intelligence.py   Cross-dump inference and evidence questions
├── compare.py        Exact block, byte, and bit comparisons
├── formats.py        MFD ↔ MCT conversion
├── profiles.py       UID-bound laboratory schemas
├── plans.py          Integrity-hashed surgical and recovery plans
├── journal.py        Durable hash-chained operation records
├── transactions.py   Prepare, verify, and recover workflows
├── storage.py        Secure immutable session storage
├── reporting.py      JSON and HTML reports
├── ui.py             Dependency-free styled terminal interface
└── cli.py            Command orchestration
```

See [Architecture](docs/ARCHITECTURE.md) and [Profile schema](docs/PROFILE_SCHEMA.md) for implementation details.

## Development

Run the complete standard-library test suite:

```bash
PYTHONPATH=src python3 -m unittest discover -v
python3 -m compileall -q src tests fcoin.py
```

The suite covers:

- Mini, 1K, and 4K geometry.
- Every access-condition triplet.
- Corrupt redundant access bits.
- Signed value-block boundaries.
- Every address redundancy byte.
- Exact decimal scaling.
- MFD/MCT round trips.
- Explainable detection and comparison.
- UID/profile authorization.
- Surgical collateral protection.
- Plan-hash tampering.
- Snapshot permissions and mismatched reads.
- Journal tampering.
- Successful verification and failed-session recovery.

## Important limitations

- No software can guarantee recovery from physical card failure or interrupted sector-trailer changes.
- `mfoc` works only where its attack assumptions and at least one usable known key are satisfied.
- A valid MIFARE value block does not prove that the value represents money.
- The manufacturer BCC indication is based on the four-byte UID-prefix layout; other UID layouts may show it as a variant.
- FCOIN prepares and verifies block-wise writes but does not hide external writer behavior. Confirm that your chosen tool writes only the listed blocks.

## Responsible disclosure

Do not publish card dumps, keys, personally identifying data, or reproducible details of a live vulnerable system. See [SECURITY.md](SECURITY.md) for reporting guidance.

## License

MIT. See [LICENSE](LICENSE).
