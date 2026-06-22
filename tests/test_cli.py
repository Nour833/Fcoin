import unittest
from io import StringIO
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch

from fcoin.analysis import analyze
from fcoin.acquisition import AcquisitionResult
from fcoin.cli import (
    _missing_arguments,
    _normalize_argv,
    _summary_rows,
    build_parser,
    command_inspect,
)
from fcoin.interactive import InteractiveApp
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

    def test_write_pending_session_disables_hardware_monitoring(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = SessionStore(Path(temp))
            image = synthetic_1k()
            session = store.create(image, image, source="unit-test")
            session.update_metadata(status="write_pending")
            app = InteractiveApp(Console(color=False), store, lambda _: 0)
            app.monitor = Mock()
            app._sync_monitor_safety()
            app.monitor.set_card_polling.assert_called_once_with(
                False,
                "card polling paused while an external write or recovery is pending",
            )

    def test_command_execution_drains_monitor_before_operation(self) -> None:
        events: list[str] = []
        with tempfile.TemporaryDirectory() as temp:
            store = SessionStore(Path(temp))
            app = InteractiveApp(
                Console(color=False),
                store,
                lambda _: events.append("command") or 0,
            )
            monitor = Mock()
            monitor.pause.side_effect = lambda: events.append("pause")
            monitor.set_card_polling.side_effect = lambda *_: events.append("guard")
            monitor.resume.side_effect = lambda: events.append("resume")
            app.monitor = monitor
            status = app._execute(["doctor"], pause=False)
        self.assertEqual(status, 0)
        self.assertEqual(events, ["pause", "command", "guard", "resume"])

    def test_detected_value_profile_stays_inside_selected_session(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = SessionStore(Path(temp))
            image = synthetic_1k()
            session = store.create(image, image, source="unit-test")
            app = InteractiveApp(Console(color=False), store, lambda _: 0)
            app._choose_path = Mock()
            with (
                patch.object(app, "_select", return_value="1"),
                patch.object(app.console, "confirm", return_value=True),
                patch.object(
                    app.console,
                    "prompt",
                    side_effect=[
                        "credit",
                        "100",
                        "test credits",
                        "0.00",
                        "100.00",
                    ],
                ),
                patch.object(app.console, "info"),
                patch.object(app.console, "success"),
            ):
                profile_path = app._create_detected_profile(session)
            self.assertIsNotNone(profile_path)
            self.assertEqual(profile_path.parent, session.path)
            self.assertTrue(profile_path.is_file())
            app._choose_path.assert_not_called()


if __name__ == "__main__":
    unittest.main()
