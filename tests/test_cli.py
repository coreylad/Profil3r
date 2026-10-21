import contextlib
import io
from pathlib import Path
import runpy
import sys
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def run_cli(self, entry_point, arguments):
        core = Mock()
        output = io.StringIO()
        with patch.dict(sys.modules, {"profil3r.core": core}):
            with patch.object(sys, "argv", [entry_point, *arguments]):
                with contextlib.redirect_stdout(output):
                    if entry_point == "-m":
                        runpy.run_module("profil3r", run_name="__main__")
                    else:
                        runpy.run_path(str(ROOT / entry_point), run_name="__main__")
        return core, output.getvalue()

    def test_entry_points_forward_arguments(self):
        for entry_point in ("profil3r", "profil3r.py", "-m"):
            for arguments in (["example@example.com"], ["john", "doe"]):
                with self.subTest(entry_point=entry_point, arguments=arguments):
                    core, output = self.run_cli(entry_point, arguments)
                    core.Core.assert_called_once_with(
                        ROOT / "config.json", arguments, report_format="json", workers=4
                    )
                    core.Core.return_value.get_permutations.assert_called_once_with()
                    core.Core.return_value.run.assert_called_once_with()
                    self.assertIn("Report saved to", output)

    def test_no_arguments_prints_help_without_starting_search(self):
        for entry_point in ("profil3r", "profil3r.py", "-m"):
            with self.subTest(entry_point=entry_point):
                core, output = self.run_cli(entry_point, [])
                core.Core.assert_not_called()
                self.assertIn("usage:", output.lower())
                self.assertIn("--self-email", output)

    def test_directory_entry_point_adds_package_parent_to_search_path(self):
        with patch.object(sys, "path", [
            path for path in sys.path
            if path and Path(path).resolve() != ROOT
        ]):
            self.run_cli("profil3r", [])
            self.assertEqual(sys.path[0], str(ROOT))

    def test_custom_options_forwarded(self):
        for entry_point in ("profil3r", "profil3r.py", "-m"):
            with self.subTest(entry_point=entry_point):
                core, _ = self.run_cli(
                    entry_point, ["--workers", "2", "--format", "csv", "john"]
                )
                core.Core.assert_called_once_with(
                    ROOT / "config.json", ["john"], report_format="csv", workers=2
                )


if __name__ == "__main__":
    unittest.main()
