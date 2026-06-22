# Laboratory profile schema

Writable profiles are JSON documents bound to exact owned-card UID prefixes.

```json
{
  "name": "owned-lab-card",
  "description": "Controlled synthetic credit experiment.",
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

## Root fields

| Field | Required | Meaning |
|---|---:|---|
| `name` | yes | Stable profile name |
| `description` | no | Human-readable purpose |
| `lab_only` | yes | Must be `true` for writable profiles |
| `allowed_uids` | yes | Non-empty exact uppercase UID-prefix allowlist |
| `fields` | yes | Unique named field definitions |

## Value field

| Field | Required | Meaning |
|---|---:|---|
| `name` | yes | CLI field selector |
| `type` | yes | Must be `value_block` |
| `block` | yes | Primary absolute block number |
| `mirrors` | no | Redundant blocks updated in the same logical operation |
| `scale` | no | Integer units per displayed unit; default `1` |
| `unit` | no | Display-only unit label |
| `minimum` | no | Inclusive exact decimal lower bound |
| `maximum` | no | Inclusive exact decimal upper bound |
| `writable` | no | Must be `true` to permit a plan |

## Validation

Profiles cannot override protocol safety. FCOIN still refuses:

- Block 0.
- Sector trailers.
- Invalid or disagreeing value blocks.
- Invalid access bits.
- Write-prohibited blocks.
- Values outside signed 32-bit range.
- Excess decimal precision.
- More than four blocks in one surgical value plan.

## Interactive detected profiles

After selecting a verified backup, the interactive value editor can identify structurally valid value blocks whose access bits permit direct writes. The user chooses the candidate, scale, unit, and safety bounds. FCOIN then saves an exact-UID profile inside that same session.

Equal values in one sector are presented as possible mirrors, but grouping requires explicit confirmation. Declining the suggestion allows one primary block to be selected instead. Detection never changes `before.mfd`.
