from __future__ import annotations

from fcoin.dump import CardImage
from fcoin.value import ValueBlock


TRANSPORT_TRAILER = bytes.fromhex("FFFFFFFFFFFFFF078069FFFFFFFFFFFF")


def synthetic_1k(value: int = 1250) -> CardImage:
    data = bytearray(1024)
    uid = bytes.fromhex("DEADBEEF")
    data[0:4] = uid
    data[4] = uid[0] ^ uid[1] ^ uid[2] ^ uid[3]
    data[5:16] = bytes.fromhex("080400016E4D4581020304")
    for sector in range(16):
        trailer_block = (sector * 4) + 3
        offset = trailer_block * 16
        data[offset : offset + 16] = TRANSPORT_TRAILER
    data[4 * 16 : 5 * 16] = ValueBlock(value, 4).encode()
    data[5 * 16 : 6 * 16] = ValueBlock(value, 5).encode()
    data[8 * 16 : 9 * 16] = b"LAB CARD 2026   "
    return CardImage.from_bytes(bytes(data), source="synthetic")


def access_trailer(groups: tuple[tuple[int, int, int], ...]) -> bytes:
    if len(groups) != 4:
        raise ValueError("Four groups required.")
    b6 = b7 = b8 = 0
    for group, (c1, c2, c3) in enumerate(groups):
        b6 |= (c1 ^ 1) << group
        b6 |= (c2 ^ 1) << (4 + group)
        b7 |= (c3 ^ 1) << group
        b7 |= c1 << (4 + group)
        b8 |= c2 << group
        b8 |= c3 << (4 + group)
    return b"\xFF" * 6 + bytes((b6, b7, b8, 0x69)) + b"\xFF" * 6
