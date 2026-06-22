import itertools
import unittest

from fcoin.access import AccessConditions, DATA_PERMISSIONS, TRAILER_PERMISSIONS
from fcoin.errors import ValidationError
from tests.helpers import access_trailer


class AccessConditionTests(unittest.TestCase):
    def test_all_access_triplets_decode(self) -> None:
        triplets = tuple(itertools.product((0, 1), repeat=3))
        for triplet in triplets:
            groups = (triplet, triplet, triplet, triplet)
            decoded = AccessConditions.decode(access_trailer(groups))
            self.assertEqual(decoded.groups, groups)
            self.assertEqual(decoded.data_permissions(0), DATA_PERMISSIONS[triplet])
            self.assertEqual(decoded.trailer_permissions, TRAILER_PERMISSIONS[triplet])

    def test_redundancy_corruption_is_rejected(self) -> None:
        trailer = bytearray(access_trailer(((0, 0, 0),) * 4))
        trailer[6] ^= 0x01
        with self.assertRaises(ValidationError):
            AccessConditions.decode(bytes(trailer))


if __name__ == "__main__":
    unittest.main()
