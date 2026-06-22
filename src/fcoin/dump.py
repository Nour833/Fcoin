"""Validated MIFARE Classic dump model."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path

from fcoin.access import SectorTrailer
from fcoin.errors import ValidationError
from fcoin.geometry import Geometry, geometry_for_size


@dataclass(frozen=True, slots=True)
class ManufacturerInfo:
    uid_prefix: bytes
    bcc: int
    bcc_valid: bool
    manufacturer_data: bytes

    @property
    def uid_hex(self) -> str:
        return self.uid_prefix.hex().upper()


@dataclass(frozen=True, slots=True)
class CardImage:
    data: bytes
    geometry: Geometry
    source: str = ""

    @classmethod
    def from_bytes(cls, data: bytes, source: str = "") -> "CardImage":
        geometry = geometry_for_size(len(data))
        return cls(bytes(data), geometry, source)

    @classmethod
    def from_file(cls, path: str | Path) -> "CardImage":
        resolved = Path(path).expanduser().resolve()
        try:
            data = resolved.read_bytes()
        except OSError as exc:
            raise ValidationError(f"Could not read dump {resolved}: {exc}") from exc
        return cls.from_bytes(data, str(resolved))

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    @property
    def manufacturer(self) -> ManufacturerInfo:
        block = self.block(0)
        uid = block[0:4]
        bcc = block[4]
        expected = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]
        return ManufacturerInfo(uid, bcc, bcc == expected, block[5:16])

    def block(self, number: int) -> bytes:
        if number < 0 or number >= self.geometry.block_count:
            raise ValidationError(f"Block {number} is outside this card.")
        offset = number * 16
        return self.data[offset : offset + 16]

    def sector_trailer(self, sector: int) -> SectorTrailer:
        return SectorTrailer.decode(self.block(self.geometry.trailer_block(sector)))

    def replace_blocks(self, replacements: dict[int, bytes]) -> "CardImage":
        mutable = bytearray(self.data)
        for block, value in replacements.items():
            if len(value) != 16:
                raise ValidationError(f"Replacement for block {block} is not 16 bytes.")
            if block == 0:
                raise ValidationError("Manufacturer block 0 cannot be changed.")
            sector = self.geometry.sector_for_block(block)
            if block == self.geometry.trailer_block(sector):
                raise ValidationError("Sector trailers cannot be changed.")
            offset = block * 16
            mutable[offset : offset + 16] = value
        return CardImage.from_bytes(bytes(mutable), source=self.source)

    def write_secure(self, path: str | Path) -> Path:
        target = Path(path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_bytes(self.data)
        target.chmod(0o600)
        return target
