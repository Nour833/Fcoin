"""Guarded change plans and exact offline application."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

from fcoin.dump import CardImage
from fcoin.errors import PlanError, ValidationError
from fcoin.profiles import CardProfile
from fcoin.value import ValueBlock, decimal_to_scaled_integer


@dataclass(frozen=True, slots=True)
class BlockOperation:
    block: int
    sector: int
    original: str
    proposed: str
    reason: str

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "BlockOperation":
        try:
            operation = cls(
                block=int(raw["block"]),
                sector=int(raw["sector"]),
                original=str(raw["original"]).upper(),
                proposed=str(raw["proposed"]).upper(),
                reason=str(raw["reason"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PlanError(f"Invalid block operation: {exc}") from exc
        for name, value in (("original", operation.original), ("proposed", operation.proposed)):
            try:
                decoded = bytes.fromhex(value)
            except ValueError as exc:
                raise PlanError(f"Operation {name} is not hexadecimal.") from exc
            if len(decoded) != 16:
                raise PlanError(f"Operation {name} must encode exactly 16 bytes.")
        return operation


@dataclass(frozen=True, slots=True)
class ChangePlan:
    schema_version: int
    plan_id: str
    kind: str
    created_at: str
    source_sha256: str
    uid: str
    card_type: str
    profile_name: str
    field_name: str
    requested_value: str
    operations: tuple[BlockOperation, ...]
    authorization: str
    plan_hash: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "kind": self.kind,
            "created_at": self.created_at,
            "source_sha256": self.source_sha256,
            "uid": self.uid,
            "card_type": self.card_type,
            "profile_name": self.profile_name,
            "field_name": self.field_name,
            "requested_value": self.requested_value,
            "operations": [asdict(operation) for operation in self.operations],
            "authorization": self.authorization,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "plan_hash": self.plan_hash}

    def verify_hash(self) -> None:
        calculated = _plan_hash(self.unsigned_dict())
        if calculated != self.plan_hash:
            raise PlanError("Change-plan integrity hash is invalid.")

    def save(self, path: str | Path) -> Path:
        target = Path(path).expanduser().resolve()
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        target.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")
        target.chmod(0o600)
        return target

    @classmethod
    def load(cls, path: str | Path) -> "ChangePlan":
        resolved = Path(path).expanduser().resolve()
        try:
            raw = json.loads(resolved.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PlanError(f"Could not load plan {resolved}: {exc}") from exc
        if not isinstance(raw, dict):
            raise PlanError("Change plan must be a JSON object.")
        try:
            plan = cls(
                schema_version=int(raw["schema_version"]),
                plan_id=str(raw["plan_id"]),
                kind=str(raw["kind"]),
                created_at=str(raw["created_at"]),
                source_sha256=str(raw["source_sha256"]),
                uid=str(raw["uid"]).upper(),
                card_type=str(raw["card_type"]),
                profile_name=str(raw["profile_name"]),
                field_name=str(raw["field_name"]),
                requested_value=str(raw["requested_value"]),
                operations=tuple(
                    BlockOperation.from_dict(item) for item in raw["operations"]
                ),
                authorization=str(raw["authorization"]),
                plan_hash=str(raw["plan_hash"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PlanError(f"Invalid change plan: {exc}") from exc
        if plan.schema_version != 1:
            raise PlanError(f"Unsupported plan schema {plan.schema_version}.")
        plan.verify_hash()
        return plan


def _plan_hash(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _bounded_decimal(value: str, minimum: str | None, maximum: str | None) -> None:
    try:
        parsed = Decimal(value)
        low = Decimal(minimum) if minimum is not None else None
        high = Decimal(maximum) if maximum is not None else None
    except InvalidOperation as exc:
        raise PlanError("Profile or requested value contains an invalid decimal.") from exc
    if low is not None and parsed < low:
        raise PlanError(f"Requested value is below profile minimum {minimum}.")
    if high is not None and parsed > high:
        raise PlanError(f"Requested value is above profile maximum {maximum}.")


def create_value_plan(
    image: CardImage,
    profile: CardProfile,
    field_name: str,
    requested_value: str,
    *,
    authorization: str,
) -> ChangePlan:
    if authorization.strip() != "I OWN THIS LAB CARD":
        raise PlanError(
            "Exact authorization text required: I OWN THIS LAB CARD"
        )
    uid = image.manufacturer.uid_hex
    profile.authorize_uid(uid)
    field = profile.field(field_name)
    if not field.writable:
        raise PlanError(f"Profile field {field.name!r} is read-only.")
    _bounded_decimal(requested_value, field.minimum, field.maximum)
    encoded_value = decimal_to_scaled_integer(requested_value, field.scale)
    blocks = tuple(dict.fromkeys((field.block, *field.mirrors)))
    if not blocks or len(blocks) > 4:
        raise PlanError("A surgical value plan must target between one and four blocks.")

    decoded: list[ValueBlock] = []
    operations: list[BlockOperation] = []
    for block_number in blocks:
        sector = image.geometry.sector_for_block(block_number)
        if block_number in {0, image.geometry.trailer_block(sector)}:
            raise PlanError("Manufacturer blocks and sector trailers are never writable.")
        try:
            current = ValueBlock.decode(image.block(block_number))
            trailer = image.sector_trailer(sector)
        except ValidationError as exc:
            raise PlanError(f"Block {block_number} is not safely editable: {exc}") from exc
        group = image.geometry.access_group_for_block(block_number)
        permission = trailer.access.data_permissions(group)
        if permission.write == "never":
            raise PlanError(f"Block {block_number} access bits prohibit direct writes.")
        decoded.append(current)
        proposed = current.with_value(encoded_value).encode()
        operations.append(
            BlockOperation(
                block=block_number,
                sector=sector,
                original=image.block(block_number).hex().upper(),
                proposed=proposed.hex().upper(),
                reason=(
                    f"Profile {profile.name}/{field.name}: exact value-block update; "
                    f"encoded address {current.address} preserved"
                ),
            )
        )
    if len({value.value for value in decoded}) != 1:
        raise PlanError("Configured primary and mirror value blocks disagree; restore first.")

    unsigned = {
        "schema_version": 1,
        "plan_id": str(uuid4()),
        "kind": "authorized_lab_value_edit",
        "created_at": datetime.now(tz=UTC).isoformat(),
        "source_sha256": image.sha256,
        "uid": uid,
        "card_type": image.geometry.name,
        "profile_name": profile.name,
        "field_name": field.name,
        "requested_value": requested_value,
        "operations": [asdict(operation) for operation in operations],
        "authorization": authorization,
    }
    return ChangePlan(
        schema_version=1,
        plan_id=unsigned["plan_id"],
        kind=unsigned["kind"],
        created_at=unsigned["created_at"],
        source_sha256=unsigned["source_sha256"],
        uid=unsigned["uid"],
        card_type=unsigned["card_type"],
        profile_name=unsigned["profile_name"],
        field_name=unsigned["field_name"],
        requested_value=unsigned["requested_value"],
        operations=tuple(operations),
        authorization=unsigned["authorization"],
        plan_hash=_plan_hash(unsigned),
    )


def create_recovery_plan(
    trusted_before: CardImage,
    current: CardImage,
    *,
    authorization: str,
) -> ChangePlan:
    if authorization.strip() != "RESTORE MY OWN CARD":
        raise PlanError("Exact authorization text required: RESTORE MY OWN CARD")
    if trusted_before.geometry != current.geometry:
        raise PlanError("Recovery images have different card geometries.")
    if trusted_before.manufacturer.uid_hex != current.manufacturer.uid_hex:
        raise PlanError("Recovery images have different UID prefixes.")
    operations: list[BlockOperation] = []
    for block in range(current.geometry.block_count):
        old = trusted_before.block(block)
        present = current.block(block)
        if old == present:
            continue
        sector = current.geometry.sector_for_block(block)
        if block == 0:
            raise PlanError("Manufacturer block differs; automatic recovery is refused.")
        if block == current.geometry.trailer_block(sector):
            raise PlanError(
                f"Sector trailer {block} differs; automatic key/access recovery is refused."
            )
        operations.append(
            BlockOperation(
                block=block,
                sector=sector,
                original=present.hex().upper(),
                proposed=old.hex().upper(),
                reason="Restore exact bytes from immutable trusted snapshot",
            )
        )
    if not operations:
        raise PlanError("Current image already matches the trusted snapshot.")
    unsigned = {
        "schema_version": 1,
        "plan_id": str(uuid4()),
        "kind": "snapshot_recovery",
        "created_at": datetime.now(tz=UTC).isoformat(),
        "source_sha256": current.sha256,
        "uid": current.manufacturer.uid_hex,
        "card_type": current.geometry.name,
        "profile_name": "immutable-session-snapshot",
        "field_name": "recovery",
        "requested_value": "",
        "operations": [asdict(operation) for operation in operations],
        "authorization": authorization,
    }
    return ChangePlan(
        schema_version=1,
        plan_id=unsigned["plan_id"],
        kind=unsigned["kind"],
        created_at=unsigned["created_at"],
        source_sha256=unsigned["source_sha256"],
        uid=unsigned["uid"],
        card_type=unsigned["card_type"],
        profile_name=unsigned["profile_name"],
        field_name=unsigned["field_name"],
        requested_value=unsigned["requested_value"],
        operations=tuple(operations),
        authorization=unsigned["authorization"],
        plan_hash=_plan_hash(unsigned),
    )


def apply_plan(image: CardImage, plan: ChangePlan) -> CardImage:
    plan.verify_hash()
    if image.sha256 != plan.source_sha256:
        raise PlanError("Input image hash does not match the plan precondition.")
    if image.manufacturer.uid_hex != plan.uid:
        raise PlanError("Input image UID does not match the plan.")
    replacements: dict[int, bytes] = {}
    for operation in plan.operations:
        current = image.block(operation.block).hex().upper()
        if current != operation.original:
            raise PlanError(
                f"Block {operation.block} changed since planning; operation aborted."
            )
        replacements[operation.block] = bytes.fromhex(operation.proposed)
    result = image.replace_blocks(replacements)
    for operation in plan.operations:
        if result.block(operation.block).hex().upper() != operation.proposed:
            raise PlanError(f"Internal verification failed for block {operation.block}.")
    for block in range(image.geometry.block_count):
        if block not in replacements and image.block(block) != result.block(block):
            raise PlanError(f"Unexpected collateral change in block {block}.")
    return result
