"""Declarative, UID-bound laboratory card profiles."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from fcoin.dump import CardImage
from fcoin.errors import ProfileError, ValidationError
from fcoin.value import ValueBlock


@dataclass(frozen=True, slots=True)
class DetectedValueGroup:
    sector: int
    value: int
    blocks: tuple[int, ...]
    encoded_addresses: tuple[int, ...]
    write_modes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ValueField:
    name: str
    block: int
    mirrors: tuple[int, ...]
    scale: int
    unit: str
    minimum: str | None
    maximum: str | None
    writable: bool

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ValueField":
        try:
            if raw["type"] != "value_block":
                raise ProfileError("Only value_block fields are accepted for guarded edits.")
            return cls(
                name=str(raw["name"]),
                block=int(raw["block"]),
                mirrors=tuple(int(value) for value in raw.get("mirrors", [])),
                scale=int(raw.get("scale", 1)),
                unit=str(raw.get("unit", "units")),
                minimum=str(raw["minimum"]) if raw.get("minimum") is not None else None,
                maximum=str(raw["maximum"]) if raw.get("maximum") is not None else None,
                writable=bool(raw.get("writable", False)),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProfileError(f"Invalid value field: {exc}") from exc


@dataclass(frozen=True, slots=True)
class CardProfile:
    name: str
    description: str
    lab_only: bool
    allowed_uids: tuple[str, ...]
    fields: tuple[ValueField, ...]

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CardProfile":
        try:
            fields = tuple(ValueField.from_dict(item) for item in raw["fields"])
            profile = cls(
                name=str(raw["name"]),
                description=str(raw.get("description", "")),
                lab_only=bool(raw.get("lab_only", False)),
                allowed_uids=tuple(str(uid).upper() for uid in raw["allowed_uids"]),
                fields=fields,
            )
        except (KeyError, TypeError) as exc:
            raise ProfileError(f"Invalid profile: {exc}") from exc
        if not profile.lab_only:
            raise ProfileError("Writable profiles must explicitly set lab_only to true.")
        if not profile.allowed_uids:
            raise ProfileError("Writable profiles must bind to at least one exact UID.")
        if len({field.name for field in profile.fields}) != len(profile.fields):
            raise ProfileError("Profile field names must be unique.")
        return profile

    @classmethod
    def load(cls, path: str | Path) -> "CardProfile":
        resolved = Path(path).expanduser().resolve()
        try:
            raw = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProfileError(f"Could not load profile {resolved}: {exc}") from exc
        if not isinstance(raw, dict):
            raise ProfileError("Profile root must be a JSON object.")
        return cls.from_dict(raw)

    def field(self, name: str) -> ValueField:
        for field in self.fields:
            if field.name == name:
                return field
        available = ", ".join(field.name for field in self.fields)
        raise ProfileError(f"Unknown field {name!r}. Available fields: {available}.")

    def authorize_uid(self, uid: str) -> None:
        if uid.upper() not in self.allowed_uids:
            raise ProfileError(
                f"Card UID {uid.upper()} is not explicitly authorized by profile {self.name!r}."
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "lab_only": self.lab_only,
            "allowed_uids": list(self.allowed_uids),
            "fields": [
                {
                    "name": field.name,
                    "type": "value_block",
                    "block": field.block,
                    "mirrors": list(field.mirrors),
                    "scale": field.scale,
                    "unit": field.unit,
                    "minimum": field.minimum,
                    "maximum": field.maximum,
                    "writable": field.writable,
                }
                for field in self.fields
            ],
        }

    def save(self, path: str | Path) -> Path:
        target = Path(path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")
        target.chmod(0o600)
        return target


def detect_writable_value_groups(image: CardImage) -> tuple[DetectedValueGroup, ...]:
    grouped: dict[tuple[int, int], list[tuple[int, ValueBlock, str]]] = {}
    for sector in range(image.geometry.sector_count):
        try:
            trailer = image.sector_trailer(sector)
        except ValidationError:
            continue
        for block in image.geometry.data_blocks(sector):
            try:
                decoded = ValueBlock.decode(image.block(block))
                group = image.geometry.access_group_for_block(block)
                permission = trailer.access.data_permissions(group)
            except ValidationError:
                continue
            if permission.write == "never":
                continue
            grouped.setdefault((sector, decoded.value), []).append(
                (block, decoded, permission.write)
            )

    result = []
    for (sector, value), entries in sorted(grouped.items()):
        entries.sort(key=lambda item: item[0])
        result.append(
            DetectedValueGroup(
                sector=sector,
                value=value,
                blocks=tuple(item[0] for item in entries),
                encoded_addresses=tuple(item[1].address for item in entries),
                write_modes=tuple(item[2] for item in entries),
            )
        )
    return tuple(result)


def detected_profile(
    image: CardImage,
    group: DetectedValueGroup,
    *,
    name: str,
    field_name: str,
    scale: int,
    unit: str,
    minimum: str,
    maximum: str,
) -> CardProfile:
    raw = {
        "name": name,
        "description": (
            "UID-bound profile created from a structurally valid value block "
            "in an immutable FCOIN backup."
        ),
        "lab_only": True,
        "allowed_uids": [image.manufacturer.uid_hex],
        "fields": [
            {
                "name": field_name,
                "type": "value_block",
                "block": group.blocks[0],
                "mirrors": list(group.blocks[1:]),
                "scale": scale,
                "unit": unit,
                "minimum": minimum,
                "maximum": maximum,
                "writable": True,
            }
        ],
    }
    return CardProfile.from_dict(raw)


def profile_template(uid: str, block: int, mirrors: tuple[int, ...]) -> dict[str, Any]:
    return {
        "name": "owned-lab-card",
        "description": "UID-bound profile for an owned laboratory card.",
        "lab_only": True,
        "allowed_uids": [uid.upper()],
        "fields": [
            {
                "name": "test_value",
                "type": "value_block",
                "block": block,
                "mirrors": list(mirrors),
                "scale": 100,
                "unit": "test credits",
                "minimum": "0.00",
                "maximum": "100.00",
                "writable": True,
            }
        ],
    }
