"""MFD and Mifare Classic Tool text-dump conversion."""

from __future__ import annotations

from pathlib import Path
import re

from fcoin.dump import CardImage
from fcoin.errors import ValidationError
from fcoin.geometry import CLASSIC_1K, CLASSIC_4K, MINI, Geometry


SECTOR_HEADER = re.compile(r"^\+Sector: ([0-9]{1,2})$")
HEX_BLOCK = re.compile(r"^[0-9A-Fa-f]{32}$")


def to_mct_text(image: CardImage) -> str:
    lines: list[str] = []
    for sector in range(image.geometry.sector_count):
        lines.append(f"+Sector: {sector}")
        first = image.geometry.first_block(sector)
        for relative in range(image.geometry.blocks_in_sector(sector)):
            lines.append(image.block(first + relative).hex().upper())
    return "\n".join(lines) + "\n"


def write_mct(image: CardImage, path: str | Path) -> Path:
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(to_mct_text(image), encoding="ascii")
    target.chmod(0o600)
    return target


def _geometry_from_sectors(sectors: dict[int, list[bytes]]) -> Geometry:
    numbers = sorted(sectors)
    if numbers == list(range(5)) and all(len(sectors[value]) == 4 for value in numbers):
        return MINI
    if numbers == list(range(16)) and all(len(sectors[value]) == 4 for value in numbers):
        return CLASSIC_1K
    if numbers == list(range(40)):
        valid = all(
            len(sectors[value]) == (16 if value >= 32 else 4) for value in numbers
        )
        if valid:
            return CLASSIC_4K
    raise ValidationError(
        "MCT dump is incomplete or has invalid sector geometry; complete Mini, 1K, or 4K "
        "images are required."
    )


def from_mct_text(text: str, source: str = "") -> CardImage:
    sectors: dict[int, list[bytes]] = {}
    current: int | None = None
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        header = SECTOR_HEADER.fullmatch(line)
        if header:
            current = int(header.group(1))
            if current in sectors:
                raise ValidationError(f"Duplicate sector {current} on line {line_number}.")
            sectors[current] = []
            continue
        if current is None:
            raise ValidationError(f"Block data before sector header on line {line_number}.")
        if not HEX_BLOCK.fullmatch(line):
            raise ValidationError(f"Invalid 16-byte hex block on line {line_number}.")
        sectors[current].append(bytes.fromhex(line))
    geometry = _geometry_from_sectors(sectors)
    data = bytearray()
    for sector in range(geometry.sector_count):
        for block in sectors[sector]:
            data.extend(block)
    return CardImage.from_bytes(bytes(data), source=source)


def read_mct(path: str | Path) -> CardImage:
    resolved = Path(path).expanduser().resolve()
    try:
        text = resolved.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise ValidationError(f"Could not read MCT dump {resolved}: {exc}") from exc
    return from_mct_text(text, str(resolved))
