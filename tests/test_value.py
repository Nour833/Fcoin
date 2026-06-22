import unittest

from fcoin.errors import ValidationError
from fcoin.value import ValueBlock, decimal_to_scaled_integer


class ValueBlockTests(unittest.TestCase):
    def test_signed_round_trip_boundaries(self) -> None:
        for value in (-(2**31), -1, 0, 1, (2**31) - 1):
            encoded = ValueBlock(value, 17).encode()
            self.assertEqual(ValueBlock.decode(encoded), ValueBlock(value, 17))

    def test_all_address_redundancy_is_validated(self) -> None:
        valid = bytearray(ValueBlock(1250, 4).encode())
        for index in range(12, 16):
            corrupted = bytearray(valid)
            corrupted[index] ^= 0x01
            with self.assertRaises(ValidationError):
                ValueBlock.decode(bytes(corrupted))

    def test_decimal_is_exact(self) -> None:
        self.assertEqual(decimal_to_scaled_integer("0.29", 100), 29)
        self.assertEqual(decimal_to_scaled_integer("-1.00", 100), -100)
        with self.assertRaises(ValidationError):
            decimal_to_scaled_integer("0.001", 100)
        with self.assertRaises(ValidationError):
            decimal_to_scaled_integer("NaN", 100)


if __name__ == "__main__":
    unittest.main()
