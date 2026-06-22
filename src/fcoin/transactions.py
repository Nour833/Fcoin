"""Preparation, verification, and recovery for externally executed block writes."""

from __future__ import annotations

import json
from pathlib import Path

from fcoin.dump import CardImage
from fcoin.errors import PlanError, VerificationError
from fcoin.journal import Journal
from fcoin.plans import ChangePlan, apply_plan, create_recovery_plan
from fcoin.storage import Session


def prepare_transaction(session: Session, plan: ChangePlan) -> Path:
    if not session.metadata().get("double_read_verified", False):
        raise PlanError(
            "Transactions require an immutable snapshot confirmed by two matching reads."
        )
    before = session.image()
    if before.sha256 != plan.source_sha256:
        raise PlanError("Plan source does not match this session's immutable snapshot.")
    intended = apply_plan(before, plan)
    plan.save(session.secure_path("write-plan.json"))
    intended_path = intended.write_secure(session.secure_path("intended.mfd"))
    journal = Journal(session.secure_path("journal.jsonl"))
    if journal.events():
        raise PlanError("This session already has a transaction journal.")
    journal.append(
        "transaction_prepared",
        plan_id=plan.plan_id,
        source_sha256=before.sha256,
        intended_sha256=intended.sha256,
        operation_count=len(plan.operations),
    )
    for operation in plan.operations:
        journal.append(
            "block_pending",
            block=operation.block,
            sector=operation.sector,
            original=operation.original,
            proposed=operation.proposed,
            reason=operation.reason,
        )
    session.update_metadata(status="write_pending", plan_id=plan.plan_id)
    instructions = {
        "warning": "Write only the listed data blocks. Never write block 0 or a sector trailer.",
        "uid": plan.uid,
        "operations": [
            {
                "block": operation.block,
                "sector": operation.sector,
                "payload": operation.proposed,
            }
            for operation in plan.operations
        ],
    }
    instruction_path = session.secure_path("write-instructions.json")
    instruction_path.write_text(json.dumps(instructions, indent=2) + "\n", encoding="utf-8")
    instruction_path.chmod(0o600)
    return intended_path


def verify_transaction(session: Session, observed: CardImage) -> None:
    before = session.image()
    intended = session.image("intended.mfd")
    plan = ChangePlan.load(session.secure_path("write-plan.json"))
    journal = Journal(session.secure_path("journal.jsonl"))
    journal.verify()
    if observed.manufacturer.uid_hex != before.manufacturer.uid_hex:
        journal.append(
            "verification_failed",
            reason="uid_mismatch",
            observed_uid=observed.manufacturer.uid_hex,
        )
        session.update_metadata(status="verification_failed")
        raise VerificationError("Observed card UID does not match the session.")

    targeted = {operation.block for operation in plan.operations}
    failures: list[str] = []
    for operation in plan.operations:
        actual = observed.block(operation.block).hex().upper()
        if actual == operation.proposed:
            journal.append("block_verified", block=operation.block, actual=actual)
        else:
            failures.append(f"block {operation.block}")
            journal.append(
                "block_verification_failed",
                block=operation.block,
                expected=operation.proposed,
                actual=actual,
            )
    collateral = [
        block
        for block in range(before.geometry.block_count)
        if block not in targeted and observed.block(block) != before.block(block)
    ]
    if collateral:
        failures.append("unexpected blocks " + ", ".join(str(value) for value in collateral))
        journal.append("collateral_change_detected", blocks=collateral)
    observed.write_secure(session.secure_path("after.mfd"))
    if failures:
        journal.append("verification_failed", reason="; ".join(failures))
        session.update_metadata(status="verification_failed")
        raise VerificationError(
            "Transaction verification failed: " + "; ".join(failures) + "."
        )
    if observed.data != intended.data:
        journal.append("verification_failed", reason="image_does_not_match_intended")
        session.update_metadata(status="verification_failed")
        raise VerificationError("Observed image does not exactly match the intended image.")
    journal.append("transaction_verified", observed_sha256=observed.sha256)
    session.update_metadata(status="write_verified", after_sha256=observed.sha256)


def recovery_plan_for_session(
    session: Session,
    current: CardImage,
    *,
    authorization: str,
) -> ChangePlan:
    journal = Journal(session.secure_path("journal.jsonl"))
    if journal.path.exists():
        journal.verify()
        journal.append("recovery_planning_started", current_sha256=current.sha256)
    plan = create_recovery_plan(
        session.image(),
        current,
        authorization=authorization,
    )
    plan.save(session.secure_path("recovery-plan.json"))
    if journal.path.exists():
        journal.append(
            "recovery_plan_created",
            plan_id=plan.plan_id,
            operation_count=len(plan.operations),
        )
    session.update_metadata(status="recovery_planned", recovery_plan_id=plan.plan_id)
    return plan
