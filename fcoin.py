#!/usr/bin/env python3
"""Compatibility launcher for running FCOIN from a source checkout."""

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# The compatibility filename matches the installed package name. When Python
# discovers this file as ``fcoin`` from a source checkout, expose the real
# package directory as its submodule path instead of shadowing it.
if __name__ == "fcoin":
    __path__ = [str(SRC / "fcoin")]
    __version__ = "2.3.0"

from fcoin.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
