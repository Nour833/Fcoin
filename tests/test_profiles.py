from pathlib import Path
import tempfile
import unittest

from fcoin.profiles import (
    CardProfile,
    detected_profile,
    detect_writable_value_groups,
)
from tests.helpers import synthetic_1k


class ProfileDetectionTests(unittest.TestCase):
    def test_detects_same_sector_value_mirrors(self) -> None:
        groups = detect_writable_value_groups(synthetic_1k(1250))
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].sector, 1)
        self.assertEqual(groups[0].value, 1250)
        self.assertEqual(groups[0].blocks, (4, 5))
        self.assertEqual(groups[0].encoded_addresses, (4, 5))

    def test_detected_profile_round_trip(self) -> None:
        image = synthetic_1k(1250)
        group = detect_writable_value_groups(image)[0]
        profile = detected_profile(
            image,
            group,
            name="detected-test",
            field_name="credit",
            scale=100,
            unit="test credits",
            minimum="0.00",
            maximum="100.00",
        )
        with tempfile.TemporaryDirectory() as temp:
            path = profile.save(Path(temp) / "credit.profile.json")
            loaded = CardProfile.load(path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        loaded.authorize_uid("DEADBEEF")
        self.assertEqual(loaded.field("credit").block, 4)
        self.assertEqual(loaded.field("credit").mirrors, (5,))


if __name__ == "__main__":
    unittest.main()
