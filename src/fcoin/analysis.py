"""Explainable, deterministic dump analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import math
import struct
from typing import Any

from fcoin.dump import CardImage
from fcoin.errors import ValidationError
from fcoin.value import ValueBlock


@dataclass(frozen=True, slots=True)
class Finding:
    kind: str
    summary: str
    confidence: float
    sector: int
    block: int
    evidence: dict[str, Any]
    severity: str = "info"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    card_type: str
    byte_size: int
    uid: str
    bcc_valid: bool
    sha256: str
    findings: tuple[Finding, ...]
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "card_type": self.card_type,
            "byte_size": self.byte_size,
            "uid": self.uid,
            "bcc_valid": self.bcc_valid,
            "sha256": self.sha256,
            "findings": [item.to_dict() for item in self.findings],
            "warnings": list(self.warnings),
        }


def _entropy(block: bytes) -> float:
    counts = [block.count(value) for value in set(block)]
    size = len(block)
    return -sum((count / size) * math.log2(count / size) for count in counts)


def _printable_text(block: bytes) -> str | None:
    printable = sum(32 <= byte <= 126 for byte in block)
    if printable < 6:
        return None
    rendered = "".join(chr(byte) if 32 <= byte <= 126 else "·" for byte in block)
    return rendered.rstrip("·\x00 ")


def _timestamp_candidates(block: bytes) -> list[tuple[str, int, str]]:
    candidates: list[tuple[str, int, str]] = []
    lower = int(datetime(2000, 1, 1, tzinfo=UTC).timestamp())
    upper = int(datetime(2100, 1, 1, tzinfo=UTC).timestamp())
    for endian, label in (("<", "little-endian"), (">", "big-endian")):
        value = struct.unpack(f"{endian}I", block[:4])[0]
        if lower <= value < upper:
            iso = datetime.fromtimestamp(value, tz=UTC).isoformat()
            candidates.append((f"32-bit {label}", value, iso))
        value64 = struct.unpack(f"{endian}Q", block[:8])[0]
        if lower <= value64 < upper:
            iso = datetime.fromtimestamp(value64, tz=UTC).isoformat()
            candidates.append((f"64-bit {label}", value64, iso))
    return candidates


def _utf16_candidates(block: bytes) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    pairs = list(zip(block[0::2], block[1::2]))
    little_ascii = bytes(first for first, second in pairs if second == 0 and 32 <= first <= 126)
    big_ascii = bytes(second for first, second in pairs if first == 0 and 32 <= second <= 126)
    if len(little_ascii) >= 3 and len(little_ascii) >= len(pairs) * 0.6:
        result.append(("utf-16-le", little_ascii.decode("ascii")))
    if len(big_ascii) >= 3 and len(big_ascii) >= len(pairs) * 0.6:
        result.append(("utf-16-be", big_ascii.decode("ascii")))
    return result


def _timestamp_context_is_plausible(block: bytes) -> bool:
    tail = block[4:]
    sparse_tail = sum(byte in {0x00, 0xFF} for byte in tail) >= 8
    repeated = block[0:4] in {block[4:8], block[8:12], block[12:16]}
    return sparse_tail or repeated


def _crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def analyze(image: CardImage) -> AnalysisReport:
    findings: list[Finding] = []
    warnings: list[str] = []
    duplicates: dict[bytes, list[int]] = {}

    manufacturer = image.manufacturer
    findings.append(
        Finding(
            kind="manufacturer",
            summary=f"Manufacturer block; UID prefix {manufacturer.uid_hex}",
            confidence=1.0,
            sector=0,
            block=0,
            evidence={"bcc_valid": manufacturer.bcc_valid},
        )
    )
    if not manufacturer.bcc_valid:
        warnings.append("Manufacturer BCC does not match the four-byte UID prefix.")

    for sector in range(image.geometry.sector_count):
        trailer_block = image.geometry.trailer_block(sector)
        try:
            trailer = image.sector_trailer(sector)
            findings.append(
                Finding(
                    kind="access_conditions",
                    summary="Valid redundant access-condition bits",
                    confidence=1.0,
                    sector=sector,
                    block=trailer_block,
                    evidence={
                        "groups": [list(group) for group in trailer.access.groups],
                        "key_b_readable": trailer.access.key_b_is_readable,
                    },
                )
            )
        except ValidationError as exc:
            warnings.append(f"Sector {sector}: {exc}")
            findings.append(
                Finding(
                    kind="corrupt_access_conditions",
                    summary=str(exc),
                    confidence=1.0,
                    sector=sector,
                    block=trailer_block,
                    evidence={},
                    severity="error",
                )
            )

        for block_number in image.geometry.data_blocks(sector):
            block = image.block(block_number)
            duplicates.setdefault(block, []).append(block_number)
            if block_number == 0:
                continue
            if not any(block):
                findings.append(
                    Finding(
                        kind="empty",
                        summary="All-zero data block",
                        confidence=1.0,
                        sector=sector,
                        block=block_number,
                        evidence={},
                    )
                )
                continue
            if block == b"\xFF" * 16:
                findings.append(
                    Finding(
                        kind="erased",
                        summary="All-FF data block",
                        confidence=1.0,
                        sector=sector,
                        block=block_number,
                        evidence={},
                    )
                )
                continue

            try:
                decoded = ValueBlock.decode(block)
            except ValidationError:
                decoded = None
            if decoded is not None:
                permission: dict[str, Any] = {}
                try:
                    trailer = image.sector_trailer(sector)
                    group = image.geometry.access_group_for_block(block_number)
                    access = trailer.access.data_permissions(group)
                    permission = {
                        "read": access.read,
                        "write": access.write,
                        "increment": access.increment,
                        "decrement_restore_transfer": access.decrement_restore_transfer,
                        "application": access.application,
                    }
                except ValidationError:
                    permission = {"status": "unknown; invalid access bits"}
                findings.append(
                    Finding(
                        kind="value_block",
                        summary=f"Structurally valid signed value block: {decoded.value}",
                        confidence=1.0,
                        sector=sector,
                        block=block_number,
                        evidence={
                            "value": decoded.value,
                            "encoded_address": decoded.address,
                            "physical_block": block_number,
                            "address_matches_physical": decoded.address == block_number,
                            "permissions": permission,
                        },
                    )
                )
                continue

            text = _printable_text(block)
            if text:
                findings.append(
                    Finding(
                        kind="text",
                        summary=f"Printable text: {text}",
                        confidence=min(0.95, sum(32 <= b <= 126 for b in block) / 16),
                        sector=sector,
                        block=block_number,
                        evidence={"text": text},
                    )
                )

            if not text:
                for encoding, decoded_text in _utf16_candidates(block):
                    findings.append(
                        Finding(
                            kind="utf16_text",
                            summary=f"Possible {encoding} text: {decoded_text}",
                            confidence=0.78,
                            sector=sector,
                            block=block_number,
                            evidence={"text": decoded_text, "encoding": encoding},
                        )
                    )

            if not text and _timestamp_context_is_plausible(block):
                for endian, value, iso in _timestamp_candidates(block):
                    findings.append(
                        Finding(
                            kind="timestamp_candidate",
                            summary=f"Possible UTC timestamp: {iso}",
                            confidence=0.65,
                            sector=sector,
                            block=block_number,
                            evidence={"value": value, "endian": endian, "iso_utc": iso},
                        )
                    )

            crc = _crc16_ccitt(block[:14])
            crc_bytes = block[14:16]
            if crc_bytes in {
                crc.to_bytes(2, "little"),
                crc.to_bytes(2, "big"),
            }:
                endian = "little" if crc_bytes == crc.to_bytes(2, "little") else "big"
                findings.append(
                    Finding(
                        kind="crc16_candidate",
                        summary="Trailing bytes match CRC-16/CCITT-FALSE over bytes 0–13",
                        confidence=0.9,
                        sector=sector,
                        block=block_number,
                        evidence={"crc": f"{crc:04X}", "stored_endian": endian},
                    )
                )

            entropy = _entropy(block)
            if entropy >= 3.7:
                findings.append(
                    Finding(
                        kind="high_entropy",
                        summary=f"High-entropy binary data ({entropy:.2f} bits/byte)",
                        confidence=0.7,
                        sector=sector,
                        block=block_number,
                        evidence={"entropy": round(entropy, 4)},
                    )
                )

            if decoded is None and not text:
                findings.append(
                    Finding(
                        kind="integer_candidates",
                        summary="Binary block with integer interpretations",
                        confidence=0.35,
                        sector=sector,
                        block=block_number,
                        evidence={
                            "u32_le": int.from_bytes(block[:4], "little"),
                            "u32_be": int.from_bytes(block[:4], "big"),
                            "i32_le": int.from_bytes(block[:4], "little", signed=True),
                            "i32_be": int.from_bytes(block[:4], "big", signed=True),
                            "hex": block.hex().upper(),
                        },
                    )
                )

    for block_data, block_numbers in duplicates.items():
        if len(block_numbers) < 2 or block_data in {b"\x00" * 16, b"\xFF" * 16}:
            continue
        for block_number in block_numbers:
            sector = image.geometry.sector_for_block(block_number)
            findings.append(
                Finding(
                    kind="duplicate",
                    summary="Exact duplicate of another data block",
                    confidence=1.0,
                    sector=sector,
                    block=block_number,
                    evidence={"matching_blocks": block_numbers},
                )
            )

    findings.sort(key=lambda item: (item.block, item.kind))
    return AnalysisReport(
        card_type=image.geometry.name,
        byte_size=len(image.data),
        uid=manufacturer.uid_hex,
        bcc_valid=manufacturer.bcc_valid,
        sha256=image.sha256,
        findings=tuple(findings),
        warnings=tuple(warnings),
    )
