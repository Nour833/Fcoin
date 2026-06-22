import unittest

from fcoin.analysis import analyze
from fcoin.cli import _missing_arguments, _normalize_argv, _summary_rows, build_parser
from tests.helpers import synthetic_1k


class CliGuidanceTests(unittest.TestCase):
    def test_friendly_command_aliases(self) -> None:
        self.assertEqual(_normalize_argv(["--inspect"]), ["inspect"])
        self.assertEqual(
            _normalize_argv(["--no-color", "-inspect", "card.mfd"]),
            ["--no-color", "inspect", "card.mfd"],
        )
        self.assertEqual(_normalize_argv(["--doctor"]), ["doctor"])

    def test_incomplete_inspect_enters_guidance(self) -> None:
        args = build_parser().parse_args(["inspect"])
        self.assertEqual(_missing_arguments(args), ("dump",))

    def test_complete_inspect_has_no_missing_input(self) -> None:
        args = build_parser().parse_args(["inspect", "card.mfd"])
        self.assertEqual(_missing_arguments(args), ())

    def test_backup_requires_a_source(self) -> None:
        args = build_parser().parse_args(["backup"])
        self.assertIn("source (--reader or --from-dump)", _missing_arguments(args))

    def test_verify_import_requires_two_reads(self) -> None:
        args = build_parser().parse_args(
            ["verify-write", "--session", "session", "--observed", "after.mfd"]
        )
        self.assertEqual(_missing_arguments(args), ("confirmation",))

    def test_default_inspect_rows_hide_routine_blocks(self) -> None:
        report = analyze(synthetic_1k())
        rows = _summary_rows(report, include_all=False)
        kinds = {row[2] for row in rows}
        self.assertNotIn("empty", kinds)
        self.assertNotIn("access_conditions", kinds)
        self.assertIn("value_block", kinds)


if __name__ == "__main__":
    unittest.main()
