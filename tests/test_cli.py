import unittest
from io import StringIO
from pathlib import Path
import tempfile
from unittest.mock import patch

from fcoin.analysis import analyze
from fcoin.acquisition import AcquisitionResult
from fcoin.cli import (
    _missing_arguments,
    _normalize_argv,
    _summary_rows,
    build_parser,
    command_inspect,
)
from fcoin.storage import SessionStore
from fcoin.ui import Console
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
        self.assertEqual(
            _missing_arguments(args),
            ("source (dump, --session, or --reader)",),
        )

    def test_complete_inspect_has_no_missing_input(self) -> None:
        args = build_parser().parse_args(["inspect", "card.mfd"])
        self.assertEqual(_missing_arguments(args), ())

    def test_reader_and_session_are_complete_inspect_sources(self) -> None:
        reader = build_parser().parse_args(["inspect", "--reader"])
        session = build_parser().parse_args(["inspect", "--session", "abc"])
        self.assertEqual(_missing_arguments(reader), ())
        self.assertEqual(_missing_arguments(session), ())

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

    def test_live_inspect_creates_verified_backup(self) -> None:
        image = synthetic_1k()
        result = AcquisitionResult(image, image, "synthetic acquisition")
        with tempfile.TemporaryDirectory() as temp:
            store = SessionStore(Path(temp))
            args = build_parser().parse_args(["inspect", "--reader"])
            with (
                patch("fcoin.cli.MfocAcquirer") as acquirer,
                patch("sys.stdout", new=StringIO()),
            ):
                acquirer.return_value.acquire_verified.return_value = result
                status = command_inspect(args, Console(color=False), store)
            self.assertEqual(status, 0)
            sessions = store.list()
            self.assertEqual(len(sessions), 1)
            self.assertTrue(sessions[0].metadata()["double_read_verified"])
            self.assertEqual(sessions[0].image().data, image.data)


if __name__ == "__main__":
    unittest.main()
