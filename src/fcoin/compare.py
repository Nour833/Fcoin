"""Byte- and block-level card-image comparison."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from fcoin.dump import CardImage
from fcoin.errors import ValidationError
from fcoin.value import ValueBlock


@dataclass(frozen=True, slots=True)
class BlockChange:
    block: int
    sector: int
    before: str
    after: str
    changed_bytes: tuple[int, ...]
    changed_bits: int
    interpretation: str

    def to_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["changed_bytes"] = list(self.changed_bytes)
        return result


@dataclass(frozen=True, slots=True)
class Comparison:
    before_sha256: str
    after_sha256: str
    changes: tuple[BlockChange, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "before_sha256": self.before_sha256,
            "after_sha256": self.after_sha256,
            "change_count": len(self.changes),
            "changes": [change.to_dict() for change in self.changes],
        }


def _interpret(before: bytes, after: bytes) -> str:
    try:
        old = ValueBlock.decode(before)
        new = ValueBlock.decode(after)
    except ValidationError:
        return "binary change"
    if old.address != new.address:
        return f"value block {old.value} → {new.value}; encoded address changed"
    return f"value block {old.value} → {new.value}"


def compare_images(before: CardImage, after: CardImage) -> Comparison:
    if before.geometry != after.geometry:
        raise ValidationError("Cannot compare card images with different geometries.")
    changes: list[BlockChange] = []
    for block in range(before.geometry.block_count):
        left = before.block(block)
        right = after.block(block)
        if left == right:
            continue
        changed_bytes = tuple(index for index, pair in enumerate(zip(left, right)) if pair[0] != pair[1])
        changed_bits = sum((a ^ b).bit_count() for a, b in zip(left, right))
        changes.append(
            BlockChange(
                block=block,
                sector=before.geometry.sector_for_block(block),
                before=left.hex().upper(),
                after=right.hex().upper(),
                changed_bytes=changed_bytes,
                changed_bits=changed_bits,
                interpretation=_interpret(left, right),
            )
        )
    return Comparison(before.sha256, after.sha256, tuple(changes))
