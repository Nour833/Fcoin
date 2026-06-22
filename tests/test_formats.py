import unittest

from fcoin.formats import from_mct_text, to_mct_text
from tests.helpers import synthetic_1k


class FormatTests(unittest.TestCase):
    def test_mct_round_trip(self) -> None:
        image = synthetic_1k()
        text = to_mct_text(image)
        self.assertIn("+Sector: 0", text)
        self.assertIn("+Sector: 15", text)
        parsed = from_mct_text(text)
        self.assertEqual(parsed.data, image.data)


if __name__ == "__main__":
    unittest.main()
