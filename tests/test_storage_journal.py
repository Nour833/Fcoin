from pathlib import Path
import tempfile
import unittest

from fcoin.errors import ValidationError
from fcoin.journal import Journal
from fcoin.storage import SessionStore
from tests.helpers import synthetic_1k


class StorageAndJournalTests(unittest.TestCase):
    def test_constructing_store_is_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp) / "not-created"
            store = SessionStore(home)
            self.assertEqual(store.list(), ())
            self.assertFalse(home.exists())

    def test_snapshot_permissions_and_double_read(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = SessionStore(Path(temp))
            image = synthetic_1k()
            session = store.create(image, image, source="unit-test")
            self.assertEqual(session.secure_path("before.mfd").stat().st_mode & 0o777, 0o600)
            self.assertEqual(session.path.stat().st_mode & 0o777, 0o700)
            self.assertTrue(session.metadata()["double_read_verified"])

    def test_mismatched_reads_are_refused(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = SessionStore(Path(temp))
            with self.assertRaises(ValidationError):
                store.create(synthetic_1k(1), synthetic_1k(2), source="unit-test")

    def test_journal_tampering_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "journal.jsonl"
            journal = Journal(path)
            journal.append("one", value=1)
            journal.append("two", value=2)
            content = path.read_text().replace('"value": 1', '"value": 9')
            path.write_text(content)
            with self.assertRaises(ValidationError):
                journal.verify()


if __name__ == "__main__":
    unittest.main()
