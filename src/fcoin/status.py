"""Read-only live NFC reader and card-presence monitoring."""

from __future__ import annotations

from dataclasses import dataclass
import re
import shutil
import subprocess
import threading
import time


UID_PATTERN = re.compile(r"UID \(NFCID1\):\s*([0-9A-Fa-f ]+)")


@dataclass(frozen=True, slots=True)
class NfcStatus:
    tool_available: bool
    reader_online: bool
    card_present: bool
    uid: str | None
    detail: str
    checked_at: float


def parse_nfc_list_output(
    output: str,
    *,
    tool_available: bool = True,
    checked_at: float | None = None,
) -> NfcStatus:
    timestamp = time.monotonic() if checked_at is None else checked_at
    if not tool_available:
        return NfcStatus(False, False, False, None, "nfc-list missing", timestamp)
    if "No NFC device found" in output:
        return NfcStatus(True, False, False, None, "reader disconnected", timestamp)
    uid_match = UID_PATTERN.search(output)
    if uid_match:
        uid = "".join(uid_match.group(1).split()).upper()
        return NfcStatus(True, True, True, uid, "ISO14443A card detected", timestamp)
    reader_markers = ("NFC device:", "opened", "device claimed")
    if any(marker.casefold() in output.casefold() for marker in reader_markers):
        return NfcStatus(True, True, False, None, "reader online; no card", timestamp)
    if output.strip():
        return NfcStatus(True, True, False, None, "reader online; no card", timestamp)
    return NfcStatus(True, False, False, None, "reader status unavailable", timestamp)


def probe_nfc_status(
    timeout: float = 2.0,
    *,
    card_polling: bool = True,
    paused_detail: str = "card polling paused",
) -> NfcStatus:
    scanner = shutil.which("nfc-scan-device")
    lister = shutil.which("nfc-list")
    if not scanner and not lister:
        return parse_nfc_list_output("", tool_available=False)
    if not card_polling:
        return NfcStatus(
            True,
            False,
            False,
            None,
            paused_detail,
            time.monotonic(),
        )

    if scanner:
        try:
            scan = subprocess.run(
                [scanner],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return NfcStatus(
                True,
                False,
                False,
                None,
                "reader scan timed out",
                time.monotonic(),
            )
        scan_output = (scan.stdout + scan.stderr).strip()
        if "No NFC device found" in scan_output:
            return NfcStatus(
                True,
                False,
                False,
                None,
                "reader disconnected",
                time.monotonic(),
            )
        reader_online = bool(scan_output.strip())
    else:
        reader_online = True

    if not reader_online:
        return NfcStatus(
            True,
            False,
            False,
            None,
            "reader status unavailable",
            time.monotonic(),
        )
    if not lister:
        return NfcStatus(
            True,
            True,
            False,
            None,
            "reader online; nfc-list missing",
            time.monotonic(),
        )
    try:
        result = subprocess.run(
            [lister, "-t", "1"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return NfcStatus(
            True,
            False,
            False,
            None,
            "reader probe timed out",
            time.monotonic(),
        )
    output = (result.stdout + result.stderr).strip()
    return parse_nfc_list_output(output)


class LiveNfcMonitor:
    def __init__(self, interval: float = 0.8):
        self.interval = interval
        self._status = NfcStatus(
            bool(shutil.which("nfc-list")),
            False,
            False,
            None,
            "checking reader",
            time.monotonic(),
        )
        self._lock = threading.Lock()
        self._probe_lock = threading.Lock()
        self._stop = threading.Event()
        self._paused = threading.Event()
        self._card_polling = True
        self._paused_detail = "card polling paused"
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="fcoin-nfc-status",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def pause(self) -> None:
        self._paused.set()
        with self._probe_lock:
            pass

    def resume(self) -> None:
        self._paused.clear()

    def set_card_polling(self, enabled: bool, detail: str = "card polling paused") -> None:
        with self._lock:
            self._card_polling = enabled
            self._paused_detail = detail
            if not enabled:
                self._status = NfcStatus(
                    bool(shutil.which("nfc-list") or shutil.which("nfc-scan-device")),
                    False,
                    False,
                    None,
                    detail,
                    time.monotonic(),
                )

    def snapshot(self) -> NfcStatus:
        with self._lock:
            return self._status

    def _run(self) -> None:
        while not self._stop.is_set():
            if not self._paused.is_set():
                with self._probe_lock:
                    if not self._paused.is_set():
                        with self._lock:
                            card_polling = self._card_polling
                            paused_detail = self._paused_detail
                        status = probe_nfc_status(
                            card_polling=card_polling,
                            paused_detail=paused_detail,
                        )
                        with self._lock:
                            self._status = status
            self._stop.wait(self.interval)
