"""Exact MIFARE Classic value-block handling."""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_HALF_EVEN

from fcoin.errors import ValidationError


MIN_I32 = -(2**31)
MAX_I32 = (2**31) - 1


@dataclass(frozen=True, slots=True)
class ValueBlock:
    value: int
    address: int

    @classmethod
    def decode(cls, block: bytes) -> "ValueBlock":
        if len(block) != 16:
            raise ValidationError("A value block must contain exactly 16 bytes.")
        value_bytes = block[0:4]
        inverted_value = block[4:8]
        backup_value = block[8:12]
        if backup_value != value_bytes:
            raise ValidationError("Value-block backup value does not match.")
        if inverted_value != bytes(byte ^ 0xFF for byte in value_bytes):
            raise ValidationError("Value-block inverted value is invalid.")
        address = block[12]
        expected = bytes((address, address ^ 0xFF, address, address ^ 0xFF))
        if block[12:16] != expected:
            raise ValidationError("Value-block address redundancy is invalid.")
        return cls(int.from_bytes(value_bytes, "little", signed=True), address)

    def encode(self) -> bytes:
        if not MIN_I32 <= self.value <= MAX_I32:
            raise ValidationError("Value is outside the signed 32-bit range.")
        if not 0 <= self.address <= 0xFF:
            raise ValidationError("Value-block address must fit in one byte.")
        raw = self.value.to_bytes(4, "little", signed=True)
        inverted = bytes(byte ^ 0xFF for byte in raw)
        address = bytes(
            (self.address, self.address ^ 0xFF, self.address, self.address ^ 0xFF)
        )
        return raw + inverted + raw + address

    def with_value(self, value: int) -> "ValueBlock":
        return ValueBlock(value=value, address=self.address)


def decimal_to_scaled_integer(value: str, scale: int) -> int:
    if scale <= 0:
        raise ValidationError("Scale must be a positive integer.")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ValidationError(f"Invalid decimal value: {value!r}.") from exc
    if not parsed.is_finite():
        raise ValidationError("Value must be finite.")
    scaled = parsed * Decimal(scale)
    integral = scaled.quantize(Decimal(1), rounding=ROUND_HALF_EVEN)
    if scaled != integral:
        decimals = max(0, len(str(scale)) - 1)
        raise ValidationError(f"Value has more precision than scale {scale} permits ({decimals}).")
    result = int(integral)
    if not MIN_I32 <= result <= MAX_I32:
        raise ValidationError("Scaled value is outside the signed 32-bit range.")
    return result


def scaled_integer_to_decimal(value: int, scale: int) -> Decimal:
    if scale <= 0:
        raise ValidationError("Scale must be a positive integer.")
    return Decimal(value) / Decimal(scale)
