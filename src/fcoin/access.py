"""MIFARE Classic sector-trailer and access-condition decoding."""

from __future__ import annotations

from dataclasses import dataclass

from fcoin.errors import ValidationError


@dataclass(frozen=True, slots=True)
class DataPermissions:
    read: str
    write: str
    increment: str
    decrement_restore_transfer: str
    application: str

    def writable_with(self, key_type: str) -> bool:
        key_type = key_type.upper()
        return self.write in {key_type, "A|B"}


@dataclass(frozen=True, slots=True)
class TrailerPermissions:
    key_a_write: str
    access_read: str
    access_write: str
    key_b_read: str
    key_b_write: str


DATA_PERMISSIONS: dict[tuple[int, int, int], DataPermissions] = {
    (0, 0, 0): DataPermissions("A|B", "A|B", "A|B", "A|B", "transport"),
    (0, 1, 0): DataPermissions("A|B", "never", "never", "never", "read/write"),
    (1, 0, 0): DataPermissions("A|B", "B", "never", "never", "read/write"),
    (1, 1, 0): DataPermissions("A|B", "B", "B", "A|B", "value"),
    (0, 0, 1): DataPermissions("A|B", "never", "never", "A|B", "value"),
    (0, 1, 1): DataPermissions("B", "B", "never", "never", "read/write"),
    (1, 0, 1): DataPermissions("B", "never", "never", "never", "read/write"),
    (1, 1, 1): DataPermissions("never", "never", "never", "never", "read/write"),
}

TRAILER_PERMISSIONS: dict[tuple[int, int, int], TrailerPermissions] = {
    (0, 0, 0): TrailerPermissions("A", "A", "never", "A", "A"),
    (0, 1, 0): TrailerPermissions("never", "A", "never", "A", "never"),
    (1, 0, 0): TrailerPermissions("B", "A|B", "never", "never", "B"),
    (1, 1, 0): TrailerPermissions("never", "A|B", "never", "never", "never"),
    (0, 0, 1): TrailerPermissions("A", "A", "A", "A", "A"),
    (0, 1, 1): TrailerPermissions("B", "A|B", "B", "never", "B"),
    (1, 0, 1): TrailerPermissions("never", "A|B", "B", "never", "never"),
    (1, 1, 1): TrailerPermissions("never", "A|B", "never", "never", "never"),
}


@dataclass(frozen=True, slots=True)
class AccessConditions:
    groups: tuple[tuple[int, int, int], ...]

    @classmethod
    def decode(cls, trailer: bytes) -> "AccessConditions":
        if len(trailer) != 16:
            raise ValidationError("A sector trailer must contain exactly 16 bytes.")
        b6, b7, b8 = trailer[6], trailer[7], trailer[8]
        groups: list[tuple[int, int, int]] = []
        errors: list[str] = []
        for group in range(4):
            c1 = (b7 >> (4 + group)) & 1
            c2 = (b8 >> group) & 1
            c3 = (b8 >> (4 + group)) & 1
            inv_c1 = (b6 >> group) & 1
            inv_c2 = (b6 >> (4 + group)) & 1
            inv_c3 = (b7 >> group) & 1
            if inv_c1 != (c1 ^ 1):
                errors.append(f"group {group} C1")
            if inv_c2 != (c2 ^ 1):
                errors.append(f"group {group} C2")
            if inv_c3 != (c3 ^ 1):
                errors.append(f"group {group} C3")
            groups.append((c1, c2, c3))
        if errors:
            raise ValidationError(
                "Invalid redundant access bits: " + ", ".join(errors) + "."
            )
        return cls(tuple(groups))

    def data_permissions(self, group: int) -> DataPermissions:
        if group not in range(3):
            raise ValidationError("Data access group must be 0, 1, or 2.")
        return DATA_PERMISSIONS[self.groups[group]]

    @property
    def trailer_permissions(self) -> TrailerPermissions:
        return TRAILER_PERMISSIONS[self.groups[3]]

    @property
    def key_b_is_readable(self) -> bool:
        return self.trailer_permissions.key_b_read != "never"


@dataclass(frozen=True, slots=True)
class SectorTrailer:
    key_a: bytes
    access: AccessConditions
    user_byte: int
    key_b: bytes

    @classmethod
    def decode(cls, block: bytes) -> "SectorTrailer":
        if len(block) != 16:
            raise ValidationError("A sector trailer must contain exactly 16 bytes.")
        return cls(
            key_a=block[0:6],
            access=AccessConditions.decode(block),
            user_byte=block[9],
            key_b=block[10:16],
        )
