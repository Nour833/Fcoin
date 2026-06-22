# Architecture

FCOIN uses immutable domain objects and explicit transitions. Acquisition, interpretation, planning, writing, and verification are separate operations.

## Trust model

The immutable `before.mfd` image is the root of trust for a session. Its SHA-256 hash, UID prefix, geometry, and creation metadata become preconditions for every plan.

An analysis finding is not an authorization. A writable plan additionally requires:

1. A `lab_only` profile.
2. Exact UID binding.
3. An explicitly writable field.
4. Valid value-block structure.
5. Valid access bits.
6. A bounded exact decimal.
7. A user authorization phrase.

Live inspection follows the acquisition trust model rather than bypassing it: the card is read twice, both complete images must match, and the verified image is persisted as an immutable session snapshot before detectors run.

## Domain layers

### Protocol

- `geometry.py` maps sectors and blocks for Mini, 1K, and 4K.
- `access.py` validates complement bits and maps permissions.
- `value.py` validates and encodes the 16-byte signed value format.
- `dump.py` provides immutable complete images.

### Evidence

- `analysis.py` emits independent findings with confidence and evidence.
- `compare.py` computes exact changes.
- `intelligence.py` correlates controlled observations without assigning unsupported semantics.

### Change control

- `profiles.py` defines UID-bound field schemas.
- `plans.py` creates content-addressed operations.
- `journal.py` persists a hash chain using `flush()` and `fsync()`.
- `transactions.py` creates intended state, verifies observations, and derives recovery plans.

### Interfaces

- `acquisition.py` contains external process adapters.
- `formats.py` converts complete images.
- `reporting.py` creates archiveable output.
- `ui.py` presents styled terminal data without runtime dependencies.
- `interactive.py` provides arrow-key menus, file/session pickers, and guided workflows.
- `cli.py` connects commands to domain operations.

## Transaction states

```text
snapshot
  └─ write_pending
       ├─ write_verified
       └─ verification_failed
            └─ recovery_planned
```

Each state change is stored in `metadata.json`. Fine-grained events are appended to `journal.jsonl`.

## Journal integrity

Each event contains:

- Sequence number.
- UTC timestamp.
- Event type and payload.
- Previous event hash.
- SHA-256 hash of canonical event content.

Changing, deleting, inserting, or reordering an event invalidates verification.

## Why writing is external

FCOIN generates minimal block payloads and verifies resulting complete images. This keeps hardware-specific writer behavior outside the trusted protocol and planning core. Users can select a compatible authorized block-wise writer while retaining a consistent precondition, journal, verification, and recovery workflow.
