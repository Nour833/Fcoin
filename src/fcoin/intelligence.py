"""Cross-dump inference and evidence-backed natural-language summaries."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fcoin.analysis import AnalysisReport, analyze
from fcoin.dump import CardImage
from fcoin.errors import ValidationError
from fcoin.value import ValueBlock


@dataclass(frozen=True, slots=True)
class ValueCandidate:
    block: int
    sector: int
    values: tuple[int, ...]
    addresses: tuple[int, ...]
    changes: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "block": self.block,
            "sector": self.sector,
            "values": list(self.values),
            "addresses": list(self.addresses),
            "changes": self.changes,
        }


def infer_value_candidates(paths: list[str | Path]) -> dict[str, Any]:
    if len(paths) < 2:
        raise ValidationError("Inference requires at least two dumps.")
    images = [CardImage.from_file(path) for path in paths]
    if len({image.geometry for image in images}) != 1:
        raise ValidationError("All inference samples must use the same card geometry.")
    if len({image.manufacturer.uid_hex for image in images}) != 1:
        raise ValidationError("Inference samples must belong to the same UID prefix.")
    geometry = images[0].geometry
    candidates: list[ValueCandidate] = []
    for block in range(geometry.block_count):
        sector = geometry.sector_for_block(block)
        if block in {0, geometry.trailer_block(sector)}:
            continue
        decoded: list[ValueBlock] = []
        try:
            decoded = [ValueBlock.decode(image.block(block)) for image in images]
        except ValidationError:
            continue
        values = tuple(value.value for value in decoded)
        candidates.append(
            ValueCandidate(
                block=block,
                sector=sector,
                values=values,
                addresses=tuple(value.address for value in decoded),
                changes=len(set(values)) > 1,
            )
        )
    return {
        "card_type": geometry.name,
        "uid": images[0].manufacturer.uid_hex,
        "sample_count": len(images),
        "sample_hashes": [image.sha256 for image in images],
        "value_block_candidates": [candidate.to_dict() for candidate in candidates],
        "interpretation_notice": (
            "Structural value blocks are protocol facts. Their business meaning is unknown "
            "until an authorized controlled experiment or trusted profile supplies semantics."
        ),
    }


def answer_question(report: AnalysisReport, question: str) -> str:
    query = question.casefold()
    values = [item for item in report.findings if item.kind == "value_block"]
    timestamps = [item for item in report.findings if item.kind == "timestamp_candidate"]
    text = [item for item in report.findings if item.kind == "text"]
    corrupt = [item for item in report.findings if item.severity == "error"]

    if any(word in query for word in ("value", "wallet", "balance", "counter")):
        if not values:
            return "No structurally valid MIFARE value blocks were found."
        lines = [
            f"Block {item.block} in sector {item.sector}: "
            f"value {item.evidence['value']}, encoded address "
            f"{item.evidence['encoded_address']}."
            for item in values
        ]
        return "\n".join(lines)
    if any(word in query for word in ("corrupt", "invalid", "warning", "damage")):
        if not corrupt and not report.warnings:
            return "No deterministic structural corruption was detected."
        lines = [item.summary for item in corrupt]
        lines.extend(report.warnings)
        return "\n".join(lines)
    if any(word in query for word in ("time", "date", "timestamp")):
        if not timestamps:
            return "No plausible 32-bit Unix timestamp candidates were found."
        return "\n".join(
            f"Block {item.block}: {item.evidence['iso_utc']} "
            f"({item.evidence['endian']})."
            for item in timestamps
        )
    if any(word in query for word in ("text", "name", "vendor", "ascii")):
        if not text:
            return "No sufficiently printable text regions were found."
        return "\n".join(
            f"Block {item.block}: {item.evidence['text']}" for item in text
        )
    if any(word in query for word in ("summary", "what", "explain")):
        return (
            f"{report.card_type}, UID prefix {report.uid}, {len(report.findings)} findings, "
            f"{len(values)} valid value blocks, {len(text)} text candidates, "
            f"{len(timestamps)} timestamp candidates, and "
            f"{len(report.warnings)} structural warnings."
        )
    return (
        "I can answer evidence-backed questions about values, corruption, timestamps, "
        "text, or provide a summary. Semantic meaning requires a trusted profile."
    )
