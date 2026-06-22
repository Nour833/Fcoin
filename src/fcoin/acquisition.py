"""External NFC acquisition adapters and diagnostics."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from fcoin.dump import CardImage
from fcoin.errors import AcquisitionError, DependencyError, ValidationError


KEY_PATTERN = re.compile(r"^[0-9A-Fa-f]{12}$")


@dataclass(frozen=True, slots=True)
class AcquisitionResult:
    first: CardImage
    second: CardImage
    log: str


def dependency_status() -> dict[str, str]:
    tools = ("mfoc", "nfc-list", "nfc-mfclassic")
    return {tool: shutil.which(tool) or "missing" for tool in tools}


def reader_diagnostics(timeout: int = 15) -> tuple[int, str]:
    executable = shutil.which("nfc-list")
    if not executable:
        raise DependencyError("nfc-list is not installed.")
    try:
        result = subprocess.run(
            [executable],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise AcquisitionError("nfc-list timed out.") from exc
    output = (result.stdout + result.stderr).strip()
    return result.returncode, output


def load_key_dictionary(path: str | Path | None) -> tuple[str, ...]:
    if path is None:
        return ()
    resolved = Path(path).expanduser().resolve()
    try:
        if resolved.stat().st_mode & 0o077:
            raise ValidationError(
                "Key dictionary permissions are too broad; use chmod 600."
            )
        lines = resolved.read_text(encoding="ascii").splitlines()
    except OSError as exc:
        raise ValidationError(f"Could not read key dictionary: {exc}") from exc
    keys: list[str] = []
    for line_number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not KEY_PATTERN.fullmatch(stripped):
            raise ValidationError(f"Invalid key on line {line_number}.")
        normalized = stripped.upper()
        if normalized not in keys:
            keys.append(normalized)
    return tuple(keys)


class MfocAcquirer:
    def __init__(
        self,
        *,
        key_file: str | Path | None = None,
        probes: int = 50,
        timeout: int = 600,
    ):
        executable = shutil.which("mfoc")
        if not executable:
            raise DependencyError(
                "mfoc is not installed. Install it using your operating-system package manager."
            )
        if probes < 1 or probes > 10000:
            raise ValidationError("Probe count must be between 1 and 10000.")
        self.executable = executable
        self.keys = load_key_dictionary(key_file)
        self.probes = probes
        self.timeout = timeout

    def _read_once(self, destination: Path) -> tuple[CardImage, str]:
        command = [
            self.executable,
            "-P",
            str(self.probes),
            "-O",
            str(destination),
        ]
        for key in self.keys:
            command.extend(["-k", key])
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AcquisitionError(f"mfoc timed out after {self.timeout} seconds.") from exc
        log = (result.stdout + result.stderr).strip()
        if result.returncode != 0:
            raise AcquisitionError(f"mfoc failed with exit code {result.returncode}.\n{log}")
        if not destination.is_file():
            raise AcquisitionError("mfoc reported success but did not create a dump.")
        return CardImage.from_file(destination), log

    def acquire_verified(self) -> AcquisitionResult:
        with tempfile.TemporaryDirectory(prefix="fcoin-", ignore_cleanup_errors=True) as temp:
            root = Path(temp)
            first, first_log = self._read_once(root / "read-1.mfd")
            second, second_log = self._read_once(root / "read-2.mfd")
            if first.data != second.data:
                raise AcquisitionError(
                    "Two independent reads differ. Card movement, unstable keys, or corruption "
                    "may be present; no backup was accepted."
                )
            return AcquisitionResult(first, second, f"{first_log}\n\n{second_log}".strip())
