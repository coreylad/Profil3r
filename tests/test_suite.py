"""Offline tests for the guided OSINT suite."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

from profil3r.suite import inspect_email, inspect_phone, save_report


class SuiteTests(unittest.TestCase):
    def test_email_rejects_invalid(self):
        with self.assertRaises(ValueError):
            inspect_email("not-an-email")

    @patch("dns.resolver.resolve")
    def test_email_syntax_and_mx(self, resolve):
        resolve.return_value = [Mock(exchange="mx.example.org.")]
        results = inspect_email("person@example.org")
        self.assertEqual(results[0]["status"], "syntax_valid")
        self.assertEqual(results[1]["status"], "mx_found")

    def test_phone_metadata(self):
        results = inspect_phone("+442071838750")
        self.assertEqual(results[0]["e164"], "+442071838750")
        self.assertIn("subscriber identity", results[0]["note"])

    def test_json_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            save_report([{"type": "phone", "status": "valid_numbering_plan"}], path, "json")
            report = json.loads(path.read_text())
            self.assertEqual(len(report["findings"]), 1)

    def test_csv_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.csv"
            save_report([{"type": "phone", "status": "valid_numbering_plan", "extra": 1}], path, "csv")
            self.assertIn("valid_numbering_plan", path.read_text())


if __name__ == "__main__":
    unittest.main()
