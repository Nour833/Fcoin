import unittest

from fcoin.errors import ValidationError
from fcoin.geometry import CLASSIC_1K, CLASSIC_4K, MINI, geometry_for_size


class GeometryTests(unittest.TestCase):
    def test_supported_sizes(self) -> None:
        self.assertEqual(geometry_for_size(320), MINI)
        self.assertEqual(geometry_for_size(1024), CLASSIC_1K)
        self.assertEqual(geometry_for_size(4096), CLASSIC_4K)

    def test_4k_large_sector_mapping(self) -> None:
        self.assertEqual(CLASSIC_4K.first_block(32), 128)
        self.assertEqual(CLASSIC_4K.trailer_block(32), 143)
        self.assertEqual(CLASSIC_4K.sector_for_block(143), 32)
        self.assertEqual(CLASSIC_4K.access_group_for_block(128), 0)
        self.assertEqual(CLASSIC_4K.access_group_for_block(133), 1)
        self.assertEqual(CLASSIC_4K.access_group_for_block(138), 2)
        self.assertEqual(CLASSIC_4K.access_group_for_block(143), 3)

    def test_invalid_size_and_block(self) -> None:
        with self.assertRaises(ValidationError):
            geometry_for_size(1000)
        with self.assertRaises(ValidationError):
            CLASSIC_1K.sector_for_block(64)


if __name__ == "__main__":
    unittest.main()
