import json
from pathlib import Path
import tempfile
import unittest

from fcoin.errors import PlanError, VerificationError
from fcoin.journal import Journal
from fcoin.plans import apply_plan, create_value_plan
from fcoin.profiles import CardProfile
from fcoin.storage import SessionStore
from fcoin.transactions import prepare_transaction, recovery_plan_for_session, verify_transaction
from fcoin.value import ValueBlock
from tests.helpers import synthetic_1k


class PlanAndTransactionTests(unittest.TestCase):
    def profile(self) -> CardProfile:
        return CardProfile.from_dict(
            {
                "name": "unit-test-card",
                "lab_only": True,
                "allowed_uids": ["DEADBEEF"],
                "fields": [
                    {
                        "name": "test_value",
                        "type": "value_block",
                        "block": 4,
                        "mirrors": [5],
                        "scale": 100,
                        "unit": "test credits",
                        "minimum": "0.00",
                        "maximum": "100.00",
                        "writable": True,
                    }
                ],
            }
        )

    def test_surgical_plan_and_offline_apply(self) -> None:
        image = synthetic_1k()
        plan = create_value_plan(
            image,
            self.profile(),
            "test_value",
            "0.29",
            authorization="I OWN THIS LAB CARD",
        )
        changed = apply_plan(image, plan)
        self.assertEqual(ValueBlock.decode(changed.block(4)).value, 29)
        self.assertEqual(ValueBlock.decode(changed.block(5)).value, 29)
        for block in range(image.geometry.block_count):
            if block not in {4, 5}:
                self.assertEqual(image.block(block), changed.block(block))

    def test_wrong_authorization_and_uid_are_rejected(self) -> None:
        with self.assertRaises(PlanError):
            create_value_plan(
                synthetic_1k(),
                self.profile(),
                "test_value",
                "1.00",
                authorization="yes",
            )

    def test_transaction_journal_and_verification(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = SessionStore(Path(temp))
            image = synthetic_1k()
            session = store.create(image, image, source="unit-test")
            plan = create_value_plan(
                image,
                self.profile(),
                "test_value",
                "50.00",
                authorization="I OWN THIS LAB CARD",
            )
            prepare_transaction(session, plan)
            intended = session.image("intended.mfd")
            verify_transaction(session, intended)
            journal = Journal(session.secure_path("journal.jsonl"))
            journal.verify()
            self.assertEqual(journal.events()[-1]["event"], "transaction_verified")
            self.assertEqual(session.metadata()["status"], "write_verified")

    def test_transaction_requires_double_read_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = SessionStore(Path(temp))
            image = synthetic_1k()
            session = store.create(image, source="single-import")
            plan = create_value_plan(
                image,
                self.profile(),
                "test_value",
                "50.00",
                authorization="I OWN THIS LAB CARD",
            )
            with self.assertRaises(PlanError):
                prepare_transaction(session, plan)

    def test_collateral_change_fails_verification_and_recovery_is_planned(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = SessionStore(Path(temp))
            image = synthetic_1k()
            session = store.create(image, image, source="unit-test")
            plan = create_value_plan(
                image,
                self.profile(),
                "test_value",
                "50.00",
                authorization="I OWN THIS LAB CARD",
            )
            prepare_transaction(session, plan)
            intended = session.image("intended.mfd")
            corrupted = intended.replace_blocks({8: b"CORRUPTED BLOCK!"})
            with self.assertRaises(VerificationError):
                verify_transaction(session, corrupted)
            recovery = recovery_plan_for_session(
                session,
                corrupted,
                authorization="RESTORE MY OWN CARD",
            )
            self.assertEqual({operation.block for operation in recovery.operations}, {4, 5, 8})

    def test_plan_hash_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "plan.json"
            plan = create_value_plan(
                synthetic_1k(),
                self.profile(),
                "test_value",
                "1.00",
                authorization="I OWN THIS LAB CARD",
            )
            plan.save(path)
            raw = json.loads(path.read_text())
            raw["requested_value"] = "99.00"
            path.write_text(json.dumps(raw))
            with self.assertRaises(PlanError):
                type(plan).load(path)


if __name__ == "__main__":
    unittest.main()
