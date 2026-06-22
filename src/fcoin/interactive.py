"""Interactive dashboard and guided command wizards."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Callable

from fcoin import __version__
from fcoin.acquisition import dependency_status
from fcoin.storage import Session, SessionStore
from fcoin.ui import Console


CommandRunner = Callable[[list[str]], int]


class ExitDashboard(Exception):
    """User requested a clean exit from interactive mode."""


@dataclass(frozen=True, slots=True)
class MenuItem:
    key: str
    label: str
    description: str
    accent: str = "cyan"


MAIN_MENU = (
    MenuItem("1", "Back up a card", "Acquire twice from a reader or import matching dumps."),
    MenuItem("2", "Inspect and understand", "Analyze, validate, ask questions, or compare images."),
    MenuItem(
        "3",
        "Reports and file tools",
        "Create reports, convert formats, infer, or inventory.",
    ),
    MenuItem(
        "4",
        "Safe laboratory editing",
        "Create profiles and surgical, UID-bound value plans.",
    ),
    MenuItem(
        "5",
        "Verify or recover",
        "Check a completed write or restore from a trusted snapshot.",
    ),
    MenuItem(
        "6",
        "Sessions and journals",
        "Review backups, transaction state, and tamper-evident logs.",
    ),
    MenuItem("7", "Reader diagnostics", "Check NFC software and whether a reader is visible."),
    MenuItem(
        "8",
        "Help and safety model",
        "Understand the workflow, controls, and direct commands.",
    ),
    MenuItem("q", "Exit FCOIN", "Leave the dashboard without changing any card or file.", "red"),
)


class InteractiveApp:
    def __init__(
        self,
        console: Console,
        store: SessionStore,
        run_command: CommandRunner,
    ):
        self.console = console
        self.store = store
        self.run_command = run_command

    def run(self, initial_command: str | None = None) -> int:
        try:
            if initial_command:
                self.run_wizard(initial_command)
                return 0
            while True:
                choice = self._select(
                    "CONTROL CENTER",
                    "Choose a workflow. Use ↑/↓ and ENTER, a number key, or q to exit.",
                    MAIN_MENU,
                    dashboard=True,
                )
                if choice in {None, "q"}:
                    self._goodbye()
                    return 0
                actions = {
                    "1": self._backup_menu,
                    "2": self._analysis_menu,
                    "3": self._tools_menu,
                    "4": self._editing_menu,
                    "5": self._recovery_menu,
                    "6": self._sessions_menu,
                    "7": lambda: self._execute(["doctor"]),
                    "8": self._help,
                }
                actions[choice]()
        except ExitDashboard:
            self._goodbye()
            return 0

    def run_wizard(self, command: str) -> None:
        wizard = {
            "inspect": self._inspect,
            "validate": self._validate,
            "compare": self._compare,
            "report": self._report,
            "convert": self._convert,
            "backup": self._backup_menu,
            "inventory": self._inventory,
            "infer": self._infer,
            "ask": self._ask,
            "profile-init": self._profile_init,
            "plan-value": self._plan_value,
            "apply-plan": self._apply_plan,
            "prepare-write": self._prepare_write,
            "verify-write": self._verify_write,
            "recover": self._recover,
            "journal": self._journal,
            "history": lambda: self._execute(["history"]),
            "doctor": lambda: self._execute(["doctor"]),
        }.get(command)
        if wizard is None:
            self.console.error(f"No guided workflow exists for {command!r}.")
            return
        wizard()

    def _dashboard_header(self, title: str, subtitle: str) -> None:
        self.console.clear()
        self.console.logo()
        p = self.console.p
        tools = dependency_status()
        tool_count = sum(path != "missing" for path in tools.values())
        session_count = len(self.store.list())
        print()
        print(
            f"  {p.slate}FCOIN {__version__}{p.reset}  "
            f"{p.slate}│{p.reset}  {p.green}{tool_count}/3 NFC tools{p.reset}  "
            f"{p.slate}│{p.reset}  {p.violet}{session_count} sessions{p.reset}"
        )
        print(f"  {p.slate}State: {self.store.home}{p.reset}")
        print(f"\n  {p.bold}{title}{p.reset}")
        print(f"  {p.dim}{subtitle}{p.reset}\n")

    def _select(
        self,
        title: str,
        subtitle: str,
        items: tuple[MenuItem, ...],
        *,
        dashboard: bool = False,
    ) -> str | None:
        if not items:
            return None
        selected = 0
        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            if dashboard:
                self._dashboard_header(title, subtitle)
            else:
                self.console.banner()
                self.console.section(title, subtitle)
            for item in items:
                print(f"  [{item.key}] {item.label} — {item.description}")
            answer = self.console.prompt("Select", items[0].key)
            return next((item.key for item in items if item.key == answer), None)

        while True:
            self._dashboard_header(title, subtitle)
            p = self.console.p
            for index, item in enumerate(items):
                accent = getattr(p, item.accent, p.cyan)
                marker = "◆" if index == selected else " "
                if index == selected:
                    print(
                        f"  {accent}{p.bold}{marker} [{item.key}] {item.label}{p.reset}"
                    )
                    print(f"      {p.white}{item.description}{p.reset}")
                else:
                    print(f"  {p.slate}{marker} [{item.key}]{p.reset} {item.label}")
                    print(f"      {p.dim}{item.description}{p.reset}")
                print()
            print(
                f"  {p.slate}↑/↓ navigate  ENTER select  1–9 shortcut  "
                f"b/ESC back  q quit{p.reset}"
            )
            key = self._read_key()
            if key in {"up", "k"}:
                selected = (selected - 1) % len(items)
            elif key in {"down", "j"}:
                selected = (selected + 1) % len(items)
            elif key == "enter":
                return items[selected].key
            elif key in {"escape", "b"}:
                return None
            elif key == "q":
                raise ExitDashboard
            else:
                for index, item in enumerate(items):
                    if key == item.key:
                        selected = index
                        return item.key

    @staticmethod
    def _read_key() -> str:
        try:
            import termios
            import tty

            descriptor = sys.stdin.fileno()
            previous = termios.tcgetattr(descriptor)
            try:
                tty.setraw(descriptor)
                char = sys.stdin.read(1)
                if not char:
                    return "q"
                if char in {"\r", "\n"}:
                    return "enter"
                if char == "\x1b":
                    second = sys.stdin.read(1)
                    if second != "[":
                        return "escape"
                    third = sys.stdin.read(1)
                    return {"A": "up", "B": "down", "C": "right", "D": "left"}.get(
                        third, "escape"
                    )
                return char.casefold()
            finally:
                termios.tcsetattr(descriptor, termios.TCSADRAIN, previous)
        except (ImportError, OSError):
            return input().strip().casefold() or "enter"

    def _execute(self, argv: list[str], *, pause: bool = True) -> int:
        self.console.clear()
        result = self.run_command(argv)
        if pause:
            self.console.pause()
        return result

    def _choose_path(
        self,
        title: str,
        suffixes: tuple[str, ...],
        *,
        directory: bool = False,
    ) -> str | None:
        current = Path.cwd()
        candidates: list[Path] = []
        if directory:
            candidates = [
                path
                for path in current.iterdir()
                if path.is_dir() and not path.name.startswith(".")
            ]
        else:
            candidates = [
                path
                for path in current.iterdir()
                if path.is_file() and path.suffix.casefold() in suffixes
            ]
        candidates.sort(key=lambda path: path.name.casefold())
        items = tuple(
            MenuItem(
                str(index + 1),
                path.name,
                str(path.resolve()),
                "green",
            )
            for index, path in enumerate(candidates[:8])
        ) + (
            MenuItem(
                "m",
                "Enter a path manually",
                "Use an absolute path or a path relative to here.",
            ),
            MenuItem("b", "Back", "Return without selecting a path.", "red"),
        )
        choice = self._select(title, f"Current directory: {current}", items)
        if choice in {None, "b", "q"}:
            return None
        if choice == "m":
            value = self.console.prompt("Path")
            return str(Path(value).expanduser()) if value else None
        index = int(choice) - 1
        return str(candidates[index].resolve())

    def _choose_session(
        self,
        title: str,
        *,
        double_read_only: bool = False,
    ) -> Session | None:
        sessions = [
            session
            for session in self.store.list()
            if not double_read_only or session.metadata().get("double_read_verified", False)
        ]
        if not sessions:
            self.console.clear()
            self.console.banner()
            self.console.warning(
                "No compatible sessions exist. Create a verified backup first."
            )
            self.console.pause()
            return None
        items = tuple(
            MenuItem(
                str(index + 1),
                f"{metadata['uid']} · {metadata.get('status', 'snapshot')}",
                f"{session.id} · {metadata['card_type']}",
                "violet",
            )
            for index, session in enumerate(sessions[:9])
            for metadata in (session.metadata(),)
        ) + (MenuItem("b", "Back", "Return without selecting a session.", "red"),)
        choice = self._select(title, "Select a secure FCOIN session.", items)
        if choice in {None, "b", "q"}:
            return None
        return sessions[int(choice) - 1]

    def _backup_menu(self) -> None:
        choice = self._select(
            "BACK UP A CARD",
            "Writable workflows require two identical independent reads.",
            (
                MenuItem(
                    "1",
                    "Read from NFC reader twice",
                    "Use mfoc and accept only matching images.",
                ),
                MenuItem(
                    "2",
                    "Import two matching dumps",
                    "Use two independently acquired MFD files.",
                ),
                MenuItem(
                    "3",
                    "Import one dump for analysis",
                    "Creates a read-only session; editing stays disabled.",
                ),
                MenuItem("b", "Back", "Return to the control center.", "red"),
            ),
        )
        if choice == "1":
            key_file = self._optional_file("Optional key dictionary", (".keys", ".txt"))
            probes = self.console.prompt("Probe count", "50")
            argv = ["backup", "--reader", "--probes", probes]
            if key_file:
                argv.extend(["--keys", key_file])
            self._execute(argv)
        elif choice in {"2", "3"}:
            first = self._choose_path("SELECT FIRST MFD DUMP", (".mfd", ".dump", ".bin"))
            if not first:
                return
            argv = ["backup", "--from-dump", first]
            if choice == "2":
                second = self._choose_path(
                    "SELECT INDEPENDENT CONFIRMATION DUMP", (".mfd", ".dump", ".bin")
                )
                if not second:
                    return
                argv.extend(["--confirmation", second])
            self._execute(argv)

    def _analysis_menu(self) -> None:
        choice = self._select(
            "INSPECT AND UNDERSTAND",
            "All analysis is deterministic and offline.",
            (
                MenuItem("1", "Inspect a dump", "Decode structure and show explainable findings."),
                MenuItem(
                    "2",
                    "Validate integrity",
                    "Check geometry, BCC indication, and access bits.",
                ),
                MenuItem("3", "Compare two dumps", "Show exact block, byte, and bit changes."),
                MenuItem("4", "Ask about a dump", "Query values, text, timestamps, or corruption."),
                MenuItem("b", "Back", "Return to the control center.", "red"),
            ),
        )
        actions = {"1": self._inspect, "2": self._validate, "3": self._compare, "4": self._ask}
        if choice in actions:
            actions[choice]()

    def _tools_menu(self) -> None:
        choice = self._select(
            "REPORTS AND FILE TOOLS",
            "Create portable evidence and organize controlled experiments.",
            (
                MenuItem("1", "Generate report", "Create a self-contained HTML or JSON report."),
                MenuItem("2", "Convert MFD ↔ MCT", "Convert complete binary and text dumps."),
                MenuItem(
                    "3",
                    "Infer across samples",
                    "Correlate valid value blocks across multiple reads.",
                ),
                MenuItem(
                    "4",
                    "Inventory a directory",
                    "Index MFD files and validate their geometry.",
                ),
                MenuItem("b", "Back", "Return to the control center.", "red"),
            ),
        )
        actions = {"1": self._report, "2": self._convert, "3": self._infer, "4": self._inventory}
        if choice in actions:
            actions[choice]()

    def _editing_menu(self) -> None:
        choice = self._select(
            "SAFE LABORATORY EDITING",
            "Only exact-UID, owned-lab profiles can produce value plans.",
            (
                MenuItem(
                    "1",
                    "Create lab profile",
                    "Bind a reviewed value field to an owned card UID.",
                ),
                MenuItem(
                    "2",
                    "Plan a value change",
                    "Validate mirrors, bounds, access bits, and exact decimal.",
                ),
                MenuItem(
                    "3",
                    "Preview a plan offline",
                    "Apply to a copy and verify no collateral changes.",
                ),
                MenuItem(
                    "4",
                    "Prepare external write",
                    "Persist the intended image and pending journal events.",
                ),
                MenuItem("b", "Back", "Return to the control center.", "red"),
            ),
        )
        actions = {
            "1": self._profile_init,
            "2": self._plan_value,
            "3": self._apply_plan,
            "4": self._prepare_write,
        }
        if choice in actions:
            actions[choice]()

    def _recovery_menu(self) -> None:
        choice = self._select(
            "VERIFY OR RECOVER",
            "Verification reads twice and checks every unrelated block.",
            (
                MenuItem("1", "Verify using NFC reader", "Acquire two matching post-write images."),
                MenuItem("2", "Verify imported reads", "Use two matching post-write MFD files."),
                MenuItem(
                    "3",
                    "Create recovery plan",
                    "Restore data blocks from an immutable snapshot.",
                ),
                MenuItem("b", "Back", "Return to the control center.", "red"),
            ),
        )
        if choice == "1":
            self._verify_write(reader=True)
        elif choice == "2":
            self._verify_write(reader=False)
        elif choice == "3":
            self._recover()

    def _sessions_menu(self) -> None:
        choice = self._select(
            "SESSIONS AND JOURNALS",
            "Review trusted snapshots and transaction evidence.",
            (
                MenuItem(
                    "1",
                    "Show session history",
                    "List card identity, state, and creation time.",
                ),
                MenuItem("2", "Open a journal", "Verify and display the event hash chain."),
                MenuItem("b", "Back", "Return to the control center.", "red"),
            ),
        )
        if choice == "1":
            self._execute(["history"])
        elif choice == "2":
            self._journal()

    def _inspect(self) -> None:
        dump = self._choose_path("SELECT DUMP TO INSPECT", (".mfd", ".dump", ".bin"))
        if not dump:
            return
        argv = ["inspect", dump]
        if self.console.confirm("Show every block and low-confidence interpretation?", False):
            argv.append("--all")
        self._execute(argv)

    def _validate(self) -> None:
        dump = self._choose_path("SELECT DUMP TO VALIDATE", (".mfd", ".dump", ".bin"))
        if dump:
            self._execute(["validate", dump])

    def _compare(self) -> None:
        before = self._choose_path("SELECT BEFORE IMAGE", (".mfd", ".dump", ".bin"))
        if not before:
            return
        after = self._choose_path("SELECT AFTER IMAGE", (".mfd", ".dump", ".bin"))
        if after:
            self._execute(["compare", before, after])

    def _ask(self) -> None:
        dump = self._choose_path("SELECT DUMP", (".mfd", ".dump", ".bin"))
        if not dump:
            return
        question = self.console.prompt(
            "Question",
            "summarize this card",
        )
        self._execute(["ask", dump, question])

    def _report(self) -> None:
        dump = self._choose_path("SELECT DUMP FOR REPORT", (".mfd", ".dump", ".bin"))
        if not dump:
            return
        format_choice = self._select(
            "REPORT FORMAT",
            "HTML is visual and self-contained; JSON is automation-friendly.",
            (
                MenuItem("1", "HTML", "Styled forensic report for viewing and archiving."),
                MenuItem("2", "JSON", "Structured report for scripts and other tools."),
                MenuItem("b", "Back", "Cancel report generation.", "red"),
            ),
        )
        if format_choice not in {"1", "2"}:
            return
        report_format = "html" if format_choice == "1" else "json"
        default = f"{Path(dump).stem}-report.{report_format}"
        output = self.console.prompt("Output file", default)
        self._execute(["report", dump, "--format", report_format, "--output", output])

    def _convert(self) -> None:
        source_format = self._select(
            "SOURCE FORMAT",
            "Choose the format of the file you already have.",
            (
                MenuItem("1", "Binary MFD", "Raw Mini, 1K, or 4K card image."),
                MenuItem("2", "MCT text dump", "Mifare Classic Tool sector text format."),
                MenuItem("b", "Back", "Cancel conversion.", "red"),
            ),
        )
        if source_format not in {"1", "2"}:
            return
        source = "mfd" if source_format == "1" else "mct"
        target = "mct" if source == "mfd" else "mfd"
        suffixes = (".mfd", ".dump", ".bin") if source == "mfd" else (".mct", ".txt")
        path = self._choose_path("SELECT FILE TO CONVERT", suffixes)
        if not path:
            return
        output = self.console.prompt("Output file", f"{Path(path).stem}.{target}")
        self._execute(["convert", path, "--from", source, "--to", target, "--output", output])

    def _inventory(self) -> None:
        directory = self._choose_path("SELECT DIRECTORY", (), directory=True)
        if not directory:
            return
        argv = ["inventory", directory]
        if self.console.confirm("Search subdirectories?", True):
            argv.append("--recursive")
        self._execute(argv)

    def _infer(self) -> None:
        dumps: list[str] = []
        while True:
            selected = self._choose_path(
                f"SELECT SAMPLE {len(dumps) + 1}",
                (".mfd", ".dump", ".bin"),
            )
            if not selected:
                break
            if selected not in dumps:
                dumps.append(selected)
            if len(dumps) >= 2 and not self.console.confirm("Add another sample?", False):
                break
        if len(dumps) < 2:
            self.console.warning("Inference needs at least two samples.")
            self.console.pause()
            return
        output = self.console.prompt("Output JSON file", "fcoin-inference.json")
        self._execute(["infer", *dumps, "--output", output])

    def _profile_init(self) -> None:
        dump = self._choose_path("SELECT OWNED LAB-CARD DUMP", (".mfd", ".dump", ".bin"))
        if not dump:
            return
        block = self.console.prompt("Primary absolute block number")
        mirrors = self.console.prompt("Mirror block numbers, comma-separated", "")
        output = self.console.prompt("Profile output file", f"{Path(dump).stem}.profile.json")
        argv = ["profile-init", dump, "--block", block, "--output", output]
        for mirror in (value.strip() for value in mirrors.split(",")):
            if mirror:
                argv.extend(["--mirror", mirror])
        self._execute(argv)

    def _plan_value(self) -> None:
        session = self._choose_session("SELECT VERIFIED SESSION", double_read_only=True)
        if not session:
            return
        profile = self._choose_path("SELECT LAB PROFILE", (".json",))
        if not profile:
            return
        field = self.console.prompt("Profile field name", "test_value")
        value = self.console.prompt("New displayed value")
        self.console.clear()
        self.console.banner()
        self.console.section("AUTHORIZATION REQUIRED")
        self.console.paragraph(
            "This operation is only for a card you own and control in a laboratory. "
            "The profile must match its exact UID and configured safety bounds.",
            indent=2,
        )
        authorization = self.console.prompt('Type exactly "I OWN THIS LAB CARD"')
        self._execute(
            [
                "plan-value",
                "--session",
                session.id,
                "--profile",
                profile,
                "--field",
                field,
                "--value",
                value,
                "--authorize",
                authorization,
            ]
        )

    def _apply_plan(self) -> None:
        dump = self._choose_path("SELECT SOURCE DUMP", (".mfd", ".dump", ".bin"))
        if not dump:
            return
        plan = self._choose_path("SELECT CHANGE PLAN", (".json",))
        if not plan:
            return
        output = self.console.prompt("Preview output", "fcoin-preview.mfd")
        self._execute(["apply-plan", dump, plan, "--output", output])

    def _prepare_write(self) -> None:
        session = self._choose_session("SELECT VERIFIED SESSION", double_read_only=True)
        if not session:
            return
        default = session.secure_path("value-plan.json")
        plan = (
            str(default)
            if default.is_file()
            else self._choose_path("SELECT CHANGE PLAN", (".json",))
        )
        if plan:
            self._execute(["prepare-write", "--session", session.id, "--plan", plan])

    def _verify_write(self, reader: bool | None = None) -> None:
        session = self._choose_session("SELECT WRITE SESSION", double_read_only=True)
        if not session:
            return
        if reader is None:
            reader = self.console.confirm(
                "Acquire verification directly from the NFC reader?",
                True,
            )
        if reader:
            key_file = self._optional_file("Optional key dictionary", (".keys", ".txt"))
            argv = ["verify-write", "--session", session.id, "--reader"]
            if key_file:
                argv.extend(["--keys", key_file])
        else:
            observed = self._choose_path("SELECT POST-WRITE READ 1", (".mfd", ".dump", ".bin"))
            if not observed:
                return
            confirmation = self._choose_path(
                "SELECT POST-WRITE READ 2", (".mfd", ".dump", ".bin")
            )
            if not confirmation:
                return
            argv = [
                "verify-write",
                "--session",
                session.id,
                "--observed",
                observed,
                "--confirmation",
                confirmation,
            ]
        self._execute(argv)

    def _recover(self) -> None:
        session = self._choose_session("SELECT TRUSTED SESSION", double_read_only=True)
        if not session:
            return
        current = self._choose_path("SELECT CURRENT CARD IMAGE", (".mfd", ".dump", ".bin"))
        if not current:
            return
        self.console.clear()
        self.console.banner()
        self.console.section("RECOVERY AUTHORIZATION")
        self.console.warning(
            "Recovery restores data blocks from the immutable snapshot and refuses trailers."
        )
        authorization = self.console.prompt('Type exactly "RESTORE MY OWN CARD"')
        self._execute(
            [
                "recover",
                "--session",
                session.id,
                "--current",
                current,
                "--authorize",
                authorization,
            ]
        )

    def _journal(self) -> None:
        session = self._choose_session("SELECT SESSION JOURNAL")
        if session:
            self._execute(["journal", "--session", session.id])

    def _optional_file(self, title: str, suffixes: tuple[str, ...]) -> str | None:
        if not self.console.confirm(f"Use {title.casefold()}?", False):
            return None
        return self._choose_path(title.upper(), suffixes)

    def _help(self) -> None:
        self.console.clear()
        self.console.logo()
        p = self.console.p
        print(f"\n  {p.bold}HOW FCOIN WORKS{p.reset}\n")
        steps = (
            ("1", "Acquire", "Two matching reads become the immutable source of truth."),
            ("2", "Understand", "Deterministic findings separate facts from candidates."),
            ("3", "Plan", "Owned-lab profiles bind fields to an exact UID and safe bounds."),
            ("4", "Record", "Every intended block is written to a durable hash-chained journal."),
            ("5", "Verify", "Two post-write reads must match the plan with no collateral changes."),
            ("6", "Recover", "Data blocks can be restored from the immutable snapshot."),
        )
        for number, title, text in steps:
            print(f"  {p.cyan}{p.bold}{number}  {title:<12}{p.reset} {text}")
        print(f"\n  {p.bold}DIRECT COMMANDS STILL WORK{p.reset}")
        print(f"  {p.dim}fcoin inspect card.mfd")
        print("  fcoin backup --reader")
        print("  fcoin compare before.mfd after.mfd")
        print(f"  fcoin --help{p.reset}")
        print(f"\n  {p.amber}Safety:{p.reset} manufacturer block 0 and sector trailers are never")
        print("  modified automatically. Value editing requires an exact-UID laboratory profile.")
        self.console.pause()

    def _goodbye(self) -> None:
        self.console.clear()
        self.console.banner()
        self.console.success("Session closed. No card operation is left running.")
