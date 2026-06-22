"""FCOIN command-line interface."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Callable

from fcoin import __version__
from fcoin.acquisition import MfocAcquirer, dependency_status, reader_diagnostics
from fcoin.analysis import analyze
from fcoin.compare import compare_images
from fcoin.dump import CardImage
from fcoin.errors import FcoinError, ValidationError
from fcoin.formats import read_mct, write_mct
from fcoin.intelligence import answer_question, infer_value_candidates
from fcoin.journal import Journal
from fcoin.plans import ChangePlan, apply_plan, create_value_plan
from fcoin.profiles import CardProfile, profile_template
from fcoin.reporting import write_html_report, write_json_report
from fcoin.storage import SessionStore
from fcoin.transactions import (
    prepare_transaction,
    recovery_plan_for_session,
    verify_transaction,
)
from fcoin.ui import Console


DESCRIPTION = (
    "Local-first MIFARE Classic backup, validation, explainable analysis, "
    "comparison, and guarded restoration."
)


def _json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def _write_json_file(path: str | Path, value: Any) -> Path:
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    target.chmod(0o600)
    return target


def _add_json_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fcoin",
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"FCOIN {__version__}")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI styling.")
    parser.add_argument(
        "--home",
        help="Override secure state directory (default: $FCOIN_HOME or ~/.local/share/fcoin).",
    )
    sub = parser.add_subparsers(dest="command")

    inspect_parser = sub.add_parser("inspect", help="Analyze a dump with explainable detectors.")
    inspect_parser.add_argument("dump")
    inspect_parser.add_argument(
        "--all", action="store_true", help="Display low-confidence binary interpretations."
    )
    _add_json_flag(inspect_parser)

    validate_parser = sub.add_parser("validate", help="Validate dump geometry and integrity.")
    validate_parser.add_argument("dump")
    _add_json_flag(validate_parser)

    compare_parser = sub.add_parser("compare", help="Show exact block and bit differences.")
    compare_parser.add_argument("before")
    compare_parser.add_argument("after")
    _add_json_flag(compare_parser)

    report_parser = sub.add_parser("report", help="Generate a JSON or self-contained HTML report.")
    report_parser.add_argument("dump")
    report_parser.add_argument("--format", choices=("html", "json"), default="html")
    report_parser.add_argument("-o", "--output", required=True)

    convert_parser = sub.add_parser(
        "convert", help="Convert complete binary MFD and MCT text dumps."
    )
    convert_parser.add_argument("input")
    convert_parser.add_argument("--from", dest="source_format", choices=("mfd", "mct"), required=True)
    convert_parser.add_argument("--to", dest="target_format", choices=("mfd", "mct"), required=True)
    convert_parser.add_argument("-o", "--output", required=True)

    backup_parser = sub.add_parser("backup", help="Create an immutable secure card snapshot.")
    source = backup_parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--from-dump", help="Import an existing MFD file.")
    source.add_argument("--reader", action="store_true", help="Acquire two matching reads with mfoc.")
    backup_parser.add_argument(
        "--confirmation", help="Second independently acquired dump for import verification."
    )
    backup_parser.add_argument("--keys", help="Optional one-key-per-line dictionary for mfoc.")
    backup_parser.add_argument("--probes", type=int, default=50)
    backup_parser.add_argument("--timeout", type=int, default=600)
    _add_json_flag(backup_parser)

    history_parser = sub.add_parser("history", help="List secure backup/write sessions.")
    _add_json_flag(history_parser)

    doctor_parser = sub.add_parser("doctor", help="Check NFC tools and reader visibility.")
    _add_json_flag(doctor_parser)

    inventory_parser = sub.add_parser("inventory", help="Index all MFD files in a directory.")
    inventory_parser.add_argument("directory")
    inventory_parser.add_argument("--recursive", action="store_true")
    _add_json_flag(inventory_parser)

    infer_parser = sub.add_parser(
        "infer", help="Find structural value-block candidates across multiple dumps."
    )
    infer_parser.add_argument("dumps", nargs="+")
    infer_parser.add_argument("-o", "--output")
    _add_json_flag(infer_parser)

    ask_parser = sub.add_parser(
        "ask", help="Ask a deterministic evidence-backed question about a dump."
    )
    ask_parser.add_argument("dump")
    ask_parser.add_argument("question")

    profile_parser = sub.add_parser(
        "profile-init", help="Create a UID-bound owned-lab-card profile template."
    )
    profile_parser.add_argument("dump")
    profile_parser.add_argument("--block", type=int, required=True)
    profile_parser.add_argument("--mirror", type=int, action="append", default=[])
    profile_parser.add_argument("-o", "--output", required=True)

    plan_parser = sub.add_parser(
        "plan-value", help="Plan a profile-bound value edit for an owned laboratory card."
    )
    plan_parser.add_argument("--session", required=True)
    plan_parser.add_argument("--profile", required=True)
    plan_parser.add_argument("--field", required=True)
    plan_parser.add_argument("--value", required=True)
    plan_parser.add_argument(
        "--authorize",
        required=True,
        help='Required exact text: "I OWN THIS LAB CARD".',
    )
    plan_parser.add_argument("-o", "--output")

    apply_parser = sub.add_parser(
        "apply-plan", help="Apply a validated plan to an offline image and verify it."
    )
    apply_parser.add_argument("dump")
    apply_parser.add_argument("plan")
    apply_parser.add_argument("-o", "--output", required=True)

    prepare_parser = sub.add_parser(
        "prepare-write",
        help="Create durable journal and exact block payloads for an external block-wise writer.",
    )
    prepare_parser.add_argument("--session", required=True)
    prepare_parser.add_argument("--plan", required=True)

    verify_parser = sub.add_parser(
        "verify-write", help="Verify a post-write card image and detect collateral changes."
    )
    verify_parser.add_argument("--session", required=True)
    observed = verify_parser.add_mutually_exclusive_group(required=True)
    observed.add_argument("--observed", help="Post-write MFD image.")
    observed.add_argument("--reader", action="store_true", help="Acquire post-write image with mfoc.")
    verify_parser.add_argument(
        "--confirmation",
        help="Second independently acquired post-write dump; required with --observed.",
    )
    verify_parser.add_argument("--keys")
    verify_parser.add_argument("--probes", type=int, default=50)
    verify_parser.add_argument("--timeout", type=int, default=600)

    recover_parser = sub.add_parser(
        "recover", help="Create a restoration plan from an immutable session snapshot."
    )
    recover_parser.add_argument("--session", required=True)
    recover_parser.add_argument("--current", required=True)
    recover_parser.add_argument(
        "--authorize",
        required=True,
        help='Required exact text: "RESTORE MY OWN CARD".',
    )
    recover_parser.add_argument("-o", "--output")

    journal_parser = sub.add_parser("journal", help="Verify and display a transaction journal.")
    journal_parser.add_argument("--session", required=True)
    _add_json_flag(journal_parser)

    return parser


def _summary_rows(report: Any, include_all: bool) -> list[tuple[object, ...]]:
    rows: list[tuple[object, ...]] = []
    excluded = {"integer_candidates"} if not include_all else set()
    for finding in report.findings:
        if finding.kind in excluded:
            continue
        rows.append(
            (
                finding.block,
                finding.sector,
                finding.kind,
                finding.summary,
                f"{finding.confidence:.0%}",
            )
        )
    return rows


def command_inspect(args: argparse.Namespace, console: Console, _: SessionStore) -> int:
    report = analyze(CardImage.from_file(args.dump))
    if args.json:
        _json(report.to_dict())
        return 0
    console.banner()
    console.section("CARD IMAGE", report.card_type)
    console.info("UID prefix", report.uid)
    console.info("SHA-256", report.sha256)
    console.info("Image size", f"{report.byte_size} bytes")
    console.info("Manufacturer BCC", "valid" if report.bcc_valid else "invalid/variant")
    if report.warnings:
        for warning in report.warnings:
            console.warning(warning)
    console.section("EXPLAINABLE FINDINGS", f"{len(report.findings)} total")
    console.table(
        ("BLOCK", "SECTOR", "TYPE", "EVIDENCE SUMMARY", "CONF."),
        _summary_rows(report, args.all),
    )
    return 0


def command_validate(args: argparse.Namespace, console: Console, _: SessionStore) -> int:
    image = CardImage.from_file(args.dump)
    report = analyze(image)
    errors = [item for item in report.findings if item.severity == "error"]
    result = {
        "valid": not errors,
        "card_type": image.geometry.name,
        "size": len(image.data),
        "uid": image.manufacturer.uid_hex,
        "sha256": image.sha256,
        "bcc_valid": image.manufacturer.bcc_valid,
        "errors": [item.to_dict() for item in errors],
        "warnings": list(report.warnings),
    }
    if args.json:
        _json(result)
    else:
        console.banner()
        console.section("VALIDATION")
        console.info("Card", image.geometry.name)
        console.info("Geometry", f"{image.geometry.sector_count} sectors")
        console.info("SHA-256", image.sha256)
        if errors:
            for error in errors:
                console.error(f"Block {error.block}: {error.summary}")
        else:
            console.success("Geometry and all redundant access bits are structurally valid.")
        for warning in report.warnings:
            console.warning(warning)
    return 1 if errors else 0


def command_compare(args: argparse.Namespace, console: Console, _: SessionStore) -> int:
    comparison = compare_images(
        CardImage.from_file(args.before),
        CardImage.from_file(args.after),
    )
    if args.json:
        _json(comparison.to_dict())
        return 0
    console.banner()
    console.section("IMAGE DIFF", f"{len(comparison.changes)} changed blocks")
    console.info("Before", comparison.before_sha256)
    console.info("After", comparison.after_sha256)
    console.table(
        ("BLOCK", "SECTOR", "BYTES", "BITS", "INTERPRETATION"),
        (
            (
                item.block,
                item.sector,
                ",".join(str(value) for value in item.changed_bytes),
                item.changed_bits,
                item.interpretation,
            )
            for item in comparison.changes
        ),
    )
    return 0


def command_report(args: argparse.Namespace, console: Console, _: SessionStore) -> int:
    report = analyze(CardImage.from_file(args.dump))
    target = (
        write_html_report(report, args.output)
        if args.format == "html"
        else write_json_report(report, args.output)
    )
    console.banner()
    console.success(f"Wrote {args.format.upper()} report to {target}")
    return 0


def command_convert(args: argparse.Namespace, console: Console, _: SessionStore) -> int:
    image = (
        CardImage.from_file(args.input)
        if args.source_format == "mfd"
        else read_mct(args.input)
    )
    if args.target_format == "mfd":
        target = image.write_secure(args.output)
    else:
        target = write_mct(image, args.output)
    console.banner()
    console.section("DUMP CONVERSION")
    console.info("Source format", args.source_format.upper())
    console.info("Target format", args.target_format.upper())
    console.info("Card", image.geometry.name)
    console.success(f"Wrote converted dump to {target}")
    return 0


def command_backup(args: argparse.Namespace, console: Console, store: SessionStore) -> int:
    if args.from_dump:
        first = CardImage.from_file(args.from_dump)
        second = CardImage.from_file(args.confirmation) if args.confirmation else None
        session = store.create(first, second, source="imported_dump")
    else:
        console.banner()
        console.section("VERIFIED ACQUISITION", "two independent matching reads required")
        console.warning("Keep the owned card stable on the reader until both reads finish.")
        result = MfocAcquirer(
            key_file=args.keys,
            probes=args.probes,
            timeout=args.timeout,
        ).acquire_verified()
        session = store.create(
            result.first,
            result.second,
            source="mfoc_double_read",
            acquisition_log=result.log,
        )
    metadata = session.metadata()
    if args.json:
        _json({"session_path": str(session.path), **metadata})
    else:
        console.banner()
        console.section("IMMUTABLE SNAPSHOT")
        console.success(f"Created session {session.id}")
        console.info("Location", session.path)
        console.info("UID prefix", metadata["uid"])
        console.info("SHA-256", metadata["sha256"])
        console.info("Double read", metadata["double_read_verified"])
    return 0


def command_history(args: argparse.Namespace, console: Console, store: SessionStore) -> int:
    records = [session.metadata() for session in store.list()]
    if args.json:
        _json(records)
        return 0
    console.banner()
    console.section("SESSION HISTORY", f"{len(records)} sessions")
    console.table(
        ("SESSION", "UID", "CARD", "STATUS", "CREATED"),
        (
            (
                item["session_id"],
                item["uid"],
                item["card_type"],
                item.get("status", "unknown"),
                item["created_at"],
            )
            for item in records
        ),
    )
    return 0


def command_doctor(args: argparse.Namespace, console: Console, _: SessionStore) -> int:
    tools = dependency_status()
    try:
        returncode, reader_output = reader_diagnostics()
    except FcoinError as exc:
        returncode, reader_output = 1, str(exc)
    result = {"tools": tools, "reader_returncode": returncode, "reader_output": reader_output}
    if args.json:
        _json(result)
        return 0 if returncode == 0 else 1
    console.banner()
    console.section("SYSTEM DIAGNOSTICS")
    for tool, location in tools.items():
        if location == "missing":
            console.warning(f"{tool}: missing")
        else:
            console.success(f"{tool}: {location}")
    console.section("READER")
    print(reader_output)
    return 0 if returncode == 0 and "No NFC device found" not in reader_output else 1


def command_inventory(args: argparse.Namespace, console: Console, _: SessionStore) -> int:
    directory = Path(args.directory).expanduser().resolve()
    if not directory.is_dir():
        raise ValidationError(f"Inventory path is not a directory: {directory}")
    pattern = "**/*.mfd" if args.recursive else "*.mfd"
    records: list[dict[str, Any]] = []
    for path in sorted(directory.glob(pattern)):
        try:
            image = CardImage.from_file(path)
            records.append(
                {
                    "path": str(path),
                    "valid": True,
                    "card_type": image.geometry.name,
                    "uid": image.manufacturer.uid_hex,
                    "sha256": image.sha256,
                }
            )
        except FcoinError as exc:
            records.append({"path": str(path), "valid": False, "error": str(exc)})
    if args.json:
        _json(records)
        return 0
    console.banner()
    console.section("DUMP INVENTORY", str(directory))
    console.table(
        ("FILE", "VALID", "UID", "CARD / ERROR"),
        (
            (
                Path(item["path"]).name,
                item["valid"],
                item.get("uid", "—"),
                item.get("card_type", item.get("error", "")),
            )
            for item in records
        ),
    )
    return 0


def command_infer(args: argparse.Namespace, console: Console, _: SessionStore) -> int:
    result = infer_value_candidates(args.dumps)
    if args.output:
        target = _write_json_file(args.output, result)
        if not args.json:
            console.banner()
            console.success(f"Wrote inference evidence to {target}")
    if args.json or not args.output:
        _json(result)
    return 0


def command_ask(args: argparse.Namespace, console: Console, _: SessionStore) -> int:
    report = analyze(CardImage.from_file(args.dump))
    console.banner()
    console.section("EVIDENCE ASSISTANT", "offline · deterministic · no network")
    console.info("Question", args.question)
    print(answer_question(report, args.question))
    return 0


def command_profile_init(args: argparse.Namespace, console: Console, _: SessionStore) -> int:
    image = CardImage.from_file(args.dump)
    if args.block == 0:
        raise ValidationError("Manufacturer block cannot be profiled as writable.")
    sector = image.geometry.sector_for_block(args.block)
    if args.block == image.geometry.trailer_block(sector):
        raise ValidationError("Sector trailer cannot be profiled as writable.")
    result = profile_template(
        image.manufacturer.uid_hex,
        args.block,
        tuple(args.mirror),
    )
    target = _write_json_file(args.output, result)
    console.banner()
    console.success(f"Created UID-bound lab profile template at {target}")
    console.warning("Review its bounds, unit, mirrors, and field name before use.")
    return 0


def command_plan_value(args: argparse.Namespace, console: Console, store: SessionStore) -> int:
    session = store.get(args.session)
    if not session.metadata().get("double_read_verified", False):
        raise ValidationError(
            "Writable plans require a snapshot confirmed by two identical independent reads."
        )
    image = session.image()
    profile = CardProfile.load(args.profile)
    plan = create_value_plan(
        image,
        profile,
        args.field,
        args.value,
        authorization=args.authorize,
    )
    target = Path(args.output).expanduser().resolve() if args.output else session.secure_path(
        "value-plan.json"
    )
    plan.save(target)
    console.banner()
    console.section("SURGICAL CHANGE PLAN", plan.plan_id)
    console.info("Source SHA-256", plan.source_sha256)
    console.info("Profile", plan.profile_name)
    console.info("Field", plan.field_name)
    console.info("Requested", plan.requested_value)
    console.table(
        ("BLOCK", "SECTOR", "BEFORE", "AFTER"),
        (
            (item.block, item.sector, item.original, item.proposed)
            for item in plan.operations
        ),
    )
    console.success(f"Saved integrity-hashed plan to {target}")
    return 0


def command_apply_plan(args: argparse.Namespace, console: Console, _: SessionStore) -> int:
    image = CardImage.from_file(args.dump)
    plan = ChangePlan.load(args.plan)
    result = apply_plan(image, plan)
    target = result.write_secure(args.output)
    console.banner()
    console.section("OFFLINE PLAN APPLIED")
    console.info("Source", image.sha256)
    console.info("Result", result.sha256)
    console.info("Changed blocks", ", ".join(str(item.block) for item in plan.operations))
    console.success(f"Wrote verified image to {target}")
    return 0


def command_prepare_write(args: argparse.Namespace, console: Console, store: SessionStore) -> int:
    session = store.get(args.session)
    plan = ChangePlan.load(args.plan)
    intended = prepare_transaction(session, plan)
    console.banner()
    console.section("TRANSACTION PREPARED", session.id)
    console.warning("Use a block-wise writer and write only the listed data blocks.")
    console.info("Intended image", intended)
    console.info("Journal", session.secure_path("journal.jsonl"))
    console.info("Instructions", session.secure_path("write-instructions.json"))
    console.success("Every operation is durably recorded as pending.")
    return 0


def command_verify_write(args: argparse.Namespace, console: Console, store: SessionStore) -> int:
    session = store.get(args.session)
    if args.observed:
        observed = CardImage.from_file(args.observed)
        if not args.confirmation:
            raise ValidationError(
                "--confirmation is required with --observed for two-read verification."
            )
        confirmation = CardImage.from_file(args.confirmation)
        if observed.data != confirmation.data:
            raise ValidationError("Post-write confirmation dumps do not match.")
    else:
        result = MfocAcquirer(
            key_file=args.keys,
            probes=args.probes,
            timeout=args.timeout,
        ).acquire_verified()
        observed = result.first
    verify_transaction(session, observed)
    console.banner()
    console.section("POST-WRITE VERIFICATION")
    console.success("Every target block matches and no collateral block changed.")
    console.info("Observed SHA-256", observed.sha256)
    return 0


def command_recover(args: argparse.Namespace, console: Console, store: SessionStore) -> int:
    session = store.get(args.session)
    current = CardImage.from_file(args.current)
    plan = recovery_plan_for_session(
        session,
        current,
        authorization=args.authorize,
    )
    target = Path(args.output).expanduser().resolve() if args.output else session.secure_path(
        "recovery-plan.json"
    )
    if target != session.secure_path("recovery-plan.json"):
        plan.save(target)
    console.banner()
    console.section("RECOVERY PLAN", plan.plan_id)
    console.info("Trusted snapshot", session.secure_path("before.mfd"))
    console.info("Blocks to restore", ", ".join(str(item.block) for item in plan.operations))
    console.success(f"Saved recovery plan to {target}")
    return 0


def command_journal(args: argparse.Namespace, console: Console, store: SessionStore) -> int:
    session = store.get(args.session)
    journal = Journal(session.secure_path("journal.jsonl"))
    journal.verify()
    events = journal.events()
    if args.json:
        _json(events)
        return 0
    console.banner()
    console.section("VERIFIED TRANSACTION JOURNAL", f"{len(events)} events")
    console.table(
        ("SEQ", "TIME", "EVENT", "DETAIL"),
        (
            (
                event["sequence"],
                event["timestamp"],
                event["event"],
                ", ".join(
                    f"{key}={value}"
                    for key, value in event.items()
                    if key
                    not in {
                        "sequence",
                        "timestamp",
                        "event",
                        "previous_hash",
                        "event_hash",
                    }
                ),
            )
            for event in events
        ),
    )
    console.success("Hash chain is intact.")
    return 0


COMMANDS: dict[str, Callable[[argparse.Namespace, Console, SessionStore], int]] = {
    "inspect": command_inspect,
    "validate": command_validate,
    "compare": command_compare,
    "report": command_report,
    "convert": command_convert,
    "backup": command_backup,
    "history": command_history,
    "doctor": command_doctor,
    "inventory": command_inventory,
    "infer": command_infer,
    "ask": command_ask,
    "profile-init": command_profile_init,
    "plan-value": command_plan_value,
    "apply-plan": command_apply_plan,
    "prepare-write": command_prepare_write,
    "verify-write": command_verify_write,
    "recover": command_recover,
    "journal": command_journal,
}


def _overview(console: Console, parser: argparse.ArgumentParser) -> None:
    console.banner()
    console.section("SAFE WORKFLOW")
    console.info("1 · Acquire", "backup --reader")
    console.info("2 · Understand", "inspect / compare / infer / ask / convert")
    console.info("3 · Plan", "profile-init / plan-value")
    console.info("4 · Record", "prepare-write")
    console.info("5 · Verify", "verify-write")
    console.info("6 · Recover", "recover")
    console.section("COMMANDS")
    parser.print_help()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console(color=False if args.no_color else None)
    if not args.command:
        _overview(console, parser)
        return 0
    try:
        store = SessionStore(args.home)
        return COMMANDS[args.command](args, console, store)
    except KeyboardInterrupt:
        console.error("Interrupted; no uncommitted in-memory operation was continued.")
        return 130
    except FcoinError as exc:
        console.error(str(exc))
        return 2
    except OSError as exc:
        console.error(f"Operating-system error: {exc}")
        return 2
