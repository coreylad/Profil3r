"""Offline regressions for streamed completions and idle progress updates."""
import contextlib
import io
import threading
import unittest
from concurrent.futures import wait as real_wait
from unittest.mock import patch

from profil3r.progress import ConsoleProgress
from profil3r.site_probe import scan_definitions
from profil3r.suite import inspect_email_sites


class ProgressTests(unittest.TestCase):
    @patch("profil3r.site_probe.probe_site")
    def test_every_completion_is_reported_by_collecting_thread(self, probe):
        probe.side_effect = lambda value, key, *args: {
            "site": key, "value": value, "status": "skipped", "attempted": False}
        calls = []
        collector = threading.get_ident()

        def progress(completed, total, finding):
            self.assertEqual(threading.get_ident(), collector)
            calls.append((completed, total, finding))

        results = scan_definitions(["exampleuser"], {"b": {}, "a": {}}, progress=progress)
        self.assertEqual([(done, total) for done, total, _ in calls], [(0, 2), (1, 2), (2, 2)])
        self.assertIsNone(calls[0][2])
        self.assertEqual({entry[2]["site"] for entry in calls[1:]}, {"a", "b"})
        self.assertEqual([result["site"] for result in results], ["a", "b"])

    @patch("profil3r.site_probe.probe_site")
    def test_idle_wait_still_emits_progress(self, probe):
        probe.return_value = {"site": "a", "value": "exampleuser", "status": "unknown"}
        calls = []
        waits = []

        def wait(pending, timeout, return_when):
            waits.append(timeout)
            if len(waits) == 1:
                return set(), pending
            return real_wait(pending, timeout=timeout, return_when=return_when)

        with patch("profil3r.site_probe.wait", side_effect=wait):
            scan_definitions(["exampleuser"], {"a": {}}, progress=lambda *args: calls.append(args))
        self.assertEqual(waits[0], 5)
        self.assertEqual(calls[:2], [(0, 1, None), (0, 1, None)])
        self.assertEqual(calls[-1][0], 1)

    def test_console_shows_elapsed_http_reasons_and_summary(self):
        output = io.StringIO()
        with patch("profil3r.progress.monotonic", side_effect=[0, 0, 5, 6, 7]):
            with contextlib.redirect_stdout(output):
                progress = ConsoleProgress("email")
                progress(0, 2, None)
                progress(0, 2, None)
                progress(1, 2, {"site": "Example", "status": "unknown", "attempted": True,
                                "http_status": 403, "detail": "Access restricted"})
                progress(2, 2, {"site": "Other", "status": "skipped", "attempted": False,
                                "detail": "Disabled upstream"})
        text = output.getvalue()
        self.assertIn("Waiting for responses; 2 unfinished", text)
        self.assertIn("50.0% | 6.0s", text)
        self.assertIn("Example: unknown HTTP 403 — Access restricted", text)
        self.assertIn("Other: skipped — Disabled upstream", text)
        self.assertIn("2 results, 1 attempted; skipped=1, unknown=1", text)

    @patch("profil3r.suite.scan_definitions")
    def test_email_scan_connects_live_reporter(self, scan):
        scan.return_value = []
        with contextlib.redirect_stdout(io.StringIO()):
            inspect_email_sites("me@example.org", workers=3)
        self.assertIsInstance(scan.call_args.kwargs["progress"], ConsoleProgress)
        self.assertEqual(scan.call_args.args[2], 3)


if __name__ == "__main__":
    unittest.main()
