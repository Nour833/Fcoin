"""Declarative, UID-bound laboratory card profiles."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from fcoin.errors import ProfileError


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
