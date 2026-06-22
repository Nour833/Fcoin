import threading
import time
import unittest
from unittest.mock import Mock, patch

from fcoin.status import (
    LiveNfcMonitor,
    NfcStatus,
    parse_nfc_list_output,
    probe_nfc_status,
)


class NfcStatusTests(unittest.TestCase):
    def test_missing_tool(self) -> None:
        status = parse_nfc_list_output("", tool_available=False, checked_at=1.0)
        self.assertFalse(status.tool_available)
        self.assertFalse(status.reader_online)
        self.assertFalse(status.card_present)

    def test_disconnected_reader(self) -> None:
        status = parse_nfc_list_output(
            "nfc-list uses libnfc 1.8.0\nNo NFC device found.",
            checked_at=1.0,
        )
        self.assertTrue(status.tool_available)
        self.assertFalse(status.reader_online)

    def test_reader_and_card_uid(self) -> None:
        status = parse_nfc_list_output(
            "NFC device: ACS / ACR122U opened\n"
            "UID (NFCID1): 04 45 35 01 DB 24 80\n",
            checked_at=1.0,
        )
        self.assertTrue(status.reader_online)
        self.assertTrue(status.card_present)
        self.assertEqual(status.uid, "04453501DB2480")

    def test_reader_without_card(self) -> None:
        status = parse_nfc_list_output(
            "NFC device: ACS / ACR122U opened\n",
            checked_at=1.0,
        )
        self.assertTrue(status.reader_online)
        self.assertFalse(status.card_present)

    def test_write_pending_mode_does_not_poll_card(self) -> None:
        scan_result = Mock(stdout="nfc-scan-device uses libnfc\n- ACR122U\n", stderr="")
        with (
            patch(
                "fcoin.status.shutil.which",
                side_effect=lambda name: f"/usr/bin/{name}",
            ),
            patch("fcoin.status.subprocess.run", return_value=scan_result) as run,
        ):
            status = probe_nfc_status(
                card_polling=False,
                paused_detail="card polling paused while write pending",
            )
        self.assertFalse(status.reader_online)
        self.assertFalse(status.card_present)
        self.assertIn("paused", status.detail)
        run.assert_not_called()

    def test_pause_waits_for_active_probe_to_finish(self) -> None:
        probe_started = threading.Event()
        release_probe = threading.Event()
        pause_finished = threading.Event()

        def slow_probe(**_: object) -> NfcStatus:
            probe_started.set()
            release_probe.wait(timeout=2)
            return NfcStatus(True, True, False, None, "done", time.monotonic())

        monitor = LiveNfcMonitor(interval=0.01)
        with patch("fcoin.status.probe_nfc_status", side_effect=slow_probe):
            monitor.start()
            self.assertTrue(probe_started.wait(timeout=1))
            pause_thread = threading.Thread(
                target=lambda: (monitor.pause(), pause_finished.set())
            )
            pause_thread.start()
            self.assertFalse(pause_finished.wait(timeout=0.05))
            release_probe.set()
            self.assertTrue(pause_finished.wait(timeout=1))
            pause_thread.join(timeout=1)
            monitor.stop()


if __name__ == "__main__":
    unittest.main()
