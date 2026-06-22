"""Dependency-free styled terminal presentation."""

from __future__ import annotations

import os
import shutil
import sys
from typing import Iterable


class Palette:
    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def code(self, value: str) -> str:
        return value if self.enabled else ""

    @property
    def reset(self) -> str:
        return self.code("\033[0m")

    @property
    def bold(self) -> str:
        return self.code("\033[1m")

    @property
    def dim(self) -> str:
        return self.code("\033[2m")

    @property
    def cyan(self) -> str:
        return self.code("\033[38;5;45m")

    @property
    def green(self) -> str:
        return self.code("\033[38;5;84m")

    @property
    def amber(self) -> str:
        return self.code("\033[38;5;221m")

    @property
    def red(self) -> str:
        return self.code("\033[38;5;203m")

    @property
    def slate(self) -> str:
        return self.code("\033[38;5;103m")

    @property
    def violet(self) -> str:
        return self.code("\033[38;5;141m")

    @property
    def white(self) -> str:
        return self.code("\033[38;5;255m")

    @property
    def inverse(self) -> str:
        return self.code("\033[7m")


class Console:
    def __init__(self, *, color: bool | None = None):
        if color is None:
            color = (
                sys.stdout.isatty()
                and os.environ.get("NO_COLOR") is None
                and os.environ.get("TERM") != "dumb"
            )
        self.p = Palette(color)

    @property
    def width(self) -> int:
        return max(72, min(shutil.get_terminal_size((100, 24)).columns, 140))

    def banner(self) -> None:
        p = self.p
        mark = (
            f"{p.cyan}◆{p.reset} {p.bold}FCOIN{p.reset} "
            f"{p.slate}/ LOCAL NFC FORENSICS{p.reset}"
        )
        rule = f"{p.slate}{'─' * min(self.width, 96)}{p.reset}"
        print(mark)
        print(rule)

    def clear(self) -> None:
        if sys.stdout.isatty():
            print("\033[2J\033[H", end="")

    def logo(self) -> None:
        p = self.p
        print(
            f"{p.cyan}{p.bold}"
            "  ███████╗ ██████╗ ██████╗ ██╗███╗   ██╗\n"
            "  ██╔════╝██╔════╝██╔═══██╗██║████╗  ██║\n"
            "  █████╗  ██║     ██║   ██║██║██╔██╗ ██║\n"
            "  ██╔══╝  ██║     ██║   ██║██║██║╚██╗██║\n"
            "  ██║     ╚██████╗╚██████╔╝██║██║ ╚████║\n"
            "  ╚═╝      ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝"
            f"{p.reset}"
        )

    def paragraph(self, text: str, indent: int = 0) -> None:
        width = max(40, min(self.width - indent, 100))
        words = text.split()
        line = " " * indent
        for word in words:
            candidate = f"{line} {word}" if line.strip() else f"{line}{word}"
            if len(candidate) > width:
                print(line)
                line = (" " * indent) + word
            else:
                line = candidate
        if line.strip():
            print(line)

    def prompt(self, label: str, default: str | None = None) -> str:
        suffix = f" {self.p.dim}[{default}]{self.p.reset}" if default else ""
        value = input(f"{self.p.cyan}›{self.p.reset} {label}{suffix}: ").strip()
        return value or (default or "")

    def confirm(self, question: str, default: bool = False) -> bool:
        hint = "Y/n" if default else "y/N"
        answer = self.prompt(f"{question} ({hint})").casefold()
        if not answer:
            return default
        return answer in {"y", "yes"}

    def pause(self, message: str = "Press ENTER to return to the menu") -> None:
        try:
            input(f"\n{self.p.slate}{message}{self.p.reset}")
        except EOFError:
            return

    def section(self, title: str, detail: str = "") -> None:
        p = self.p
        suffix = f"  {p.dim}{detail}{p.reset}" if detail else ""
        print(f"\n{p.cyan}┌─{p.reset} {p.bold}{title}{p.reset}{suffix}")

    def success(self, text: str) -> None:
        print(f"{self.p.green}✓{self.p.reset} {text}")

    def warning(self, text: str) -> None:
        print(f"{self.p.amber}⚠{self.p.reset} {text}")

    def error(self, text: str) -> None:
        print(f"{self.p.red}✕{self.p.reset} {text}", file=sys.stderr)

    def info(self, label: str, value: object) -> None:
        print(f"{self.p.slate}{label:<18}{self.p.reset} {value}")

    def table(self, headers: tuple[str, ...], rows: Iterable[tuple[object, ...]]) -> None:
        materialized = [tuple(str(cell) for cell in row) for row in rows]
        widths = [len(header) for header in headers]
        for row in materialized:
            for index, cell in enumerate(row):
                widths[index] = min(max(widths[index], len(cell)), 64)
        separator = "─┼─".join("─" * width for width in widths)
        print(
            f"{self.p.bold}"
            + " │ ".join(header.ljust(widths[index]) for index, header in enumerate(headers))
            + f"{self.p.reset}"
        )
        print(f"{self.p.slate}{separator}{self.p.reset}")
        for row in materialized:
            rendered = []
            for index, cell in enumerate(row):
                if len(cell) > widths[index]:
                    cell = cell[: max(0, widths[index] - 1)] + "…"
                rendered.append(cell.ljust(widths[index]))
            print(" │ ".join(rendered))
