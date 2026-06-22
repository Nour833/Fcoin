import unittest

from fcoin.analysis import analyze
from fcoin.compare import compare_images
from tests.helpers import synthetic_1k


class AnalysisAndComparisonTests(unittest.TestCase):
    def test_analysis_finds_value_text_and_duplicates(self) -> None:
        report = analyze(synthetic_1k())
        kinds = {finding.kind for finding in report.findings}
        self.assertIn("value_block", kinds)
        self.assertIn("text", kinds)
        values = [f for f in report.findings if f.kind == "value_block"]
        self.assertEqual({f.block for f in values}, {4, 5})
        self.assertFalse(report.warnings)

    def test_compare_interprets_value_change(self) -> None:
        before = synthetic_1k(1250)
        after = synthetic_1k(5000)
        comparison = compare_images(before, after)
        self.assertEqual({change.block for change in comparison.changes}, {4, 5})
        self.assertTrue(all("1250" in change.interpretation for change in comparison.changes))
        self.assertTrue(all("5000" in change.interpretation for change in comparison.changes))


if __name__ == "__main__":
    unittest.main()
