import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

from profil3r.core import Core
from profil3r.mailaccess_adapter import investigate_with_mailaccess


class IntegrationTests(unittest.TestCase):
    @patch("profil3r.core.scan_public_profiles")
    @patch("profil3r.core.load_sites")
    def test_standard_run_includes_adult_checks(self, load, scan):
        load.return_value = {"Example": {"url": "https://example.org/{username}"}}
        scan.return_value = [{"site": "Example", "url": "https://example.org/jane",
                              "status": "unknown", "http_status": 200}]
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "config.json"
            config.write_text(json.dumps({"report_path": str(Path(directory) / "{}.json")}))
            core = Core(config, ["Jane"], workers=2)
            core.get_permutations()
            result = core.adult_public_profiles()
        self.assertEqual(result["checked"], 1)
        self.assertEqual(result["status_counts"]["unknown"], 1)
        self.assertEqual(result["accounts"], [])

    @patch("profil3r.mailaccess_adapter.shutil.which", return_value=None)
    def test_mailaccess_requires_optional_install(self, _which):
        with self.assertRaisesRegex(RuntimeError, "not installed"):
            investigate_with_mailaccess("me@example.org")

    @patch("profil3r.mailaccess_adapter.shutil.which", return_value="/usr/bin/mailaccess")
    @patch("profil3r.mailaccess_adapter.subprocess.run")
    def test_mailaccess_reads_upstream_json(self, run, _which):
        def write_report(command, **kwargs):
            Path(command[-1]).write_text('{"findings": []}')
            return Mock(returncode=0)
        run.side_effect = write_report
        result = investigate_with_mailaccess("me@example.org")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["report"]["findings"], [])
        self.assertEqual(run.call_args.args[0][1:3], ["investigate", "me@example.org"])


if __name__ == "__main__":
    unittest.main()
