"""MIFARE Classic memory geometry."""

from __future__ import annotations

from dataclasses import dataclass

from fcoin.errors import ValidationError


@dataclass(frozen=True, slots=True)
class Geometry:
    name: str
    byte_size: int
    sector_count: int

    @property
    def block_count(self) -> int:
        return self.byte_size // 16

    def blocks_in_sector(self, sector: int) -> int:
        self._check_sector(sector)
        if self.name == "MIFARE Classic 4K" and sector >= 32:
            return 16
        return 4

    def first_block(self, sector: int) -> int:
        self._check_sector(sector)
        if self.name == "MIFARE Classic 4K" and sector >= 32:
            return 128 + ((sector - 32) * 16)
        return sector * 4

    def trailer_block(self, sector: int) -> int:
        return self.first_block(sector) + self.blocks_in_sector(sector) - 1

    def sector_for_block(self, block: int) -> int:
        if block < 0 or block >= self.block_count:
            raise ValidationError(f"Block {block} is outside {self.name}.")
        if self.name == "MIFARE Classic 4K" and block >= 128:
            return 32 + ((block - 128) // 16)
        return block // 4

    def access_group_for_block(self, block: int) -> int:
        sector = self.sector_for_block(block)
        relative = block - self.first_block(sector)
        if relative == self.blocks_in_sector(sector) - 1:
            return 3
        if self.blocks_in_sector(sector) == 4:
            return relative
        return min(relative // 5, 2)

    def data_blocks(self, sector: int) -> tuple[int, ...]:
        first = self.first_block(sector)
        trailer = self.trailer_block(sector)
        return tuple(range(first, trailer))

    def _check_sector(self, sector: int) -> None:
        if sector < 0 or sector >= self.sector_count:
            raise ValidationError(f"Sector {sector} is outside {self.name}.")


MINI = Geometry("MIFARE Classic Mini", 320, 5)
CLASSIC_1K = Geometry("MIFARE Classic 1K", 1024, 16)
CLASSIC_4K = Geometry("MIFARE Classic 4K", 4096, 40)
GEOMETRIES = {g.byte_size: g for g in (MINI, CLASSIC_1K, CLASSIC_4K)}


def geometry_for_size(size: int) -> Geometry:
    try:
        return GEOMETRIES[size]
    except KeyError as exc:
        supported = ", ".join(str(value) for value in sorted(GEOMETRIES))
        raise ValidationError(
            f"Unsupported dump size {size} bytes. Expected one of: {supported}."
        ) from exc
