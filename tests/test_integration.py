import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

from profil3r.core import Core
from profil3r.mailaccess_adapter import investigate_with_mailaccess


class IntegrationTests(unittest.TestCase):
    @patch("profil3r.core.scan_definitions")
    @patch("profil3r.core.load_definitions")
    def test_standard_run_includes_adult_checks(self, load, scan):
        load.return_value = {"Example": {"url": "https://example.org/{username}", "category": "adult"}}
        scan.return_value = [{"site": "Example", "url": "https://example.org/jane",
                              "status": "unknown", "http_status": 200, "attempted": True}]
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(json.dumps({"report_path": str(Path(directory) / "{}.json")}))
            core = Core(config, ["Jane"], workers=2)
            core.get_permutations()
            result = core.adult_public_profiles()
        self.assertEqual(result["checked"], 1)
        self.assertEqual(result["status_counts"]["unknown"], 1)
        self.assertEqual(result["accounts"], [])

    @patch("profil3r.mailaccess_adapter.scan_definitions")
    def test_mailaccess_compatibility_uses_native_runner(self, scan):
        scan.return_value = [{"status": "unknown"}]
        result = investigate_with_mailaccess("me@example.org")
        self.assertEqual(result["engine"], "profil3r-native")
        self.assertEqual(result["report"]["findings"], scan.return_value)
        self.assertEqual(len(scan.call_args.args[1]), 260)


if __name__ == "__main__":
    unittest.main()
