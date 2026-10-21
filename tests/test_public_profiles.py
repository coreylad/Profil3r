"""Offline regression tests for public profile matching."""
import unittest
from unittest.mock import Mock, patch

from profil3r.public_profiles import check_profile, scan_public_profiles


class PublicProfileTests(unittest.TestCase):
    def setUp(self):
        self.site = {
            "url": "https://example.org/users/{username}",
            "check_text": ["Profile for"],
            "not_found_text": ["No such user"],
        }

    @patch("profil3r.public_profiles.requests.get")
    def test_positive_indicator_is_only_possible_match(self, get):
        get.return_value = Mock(status_code=200, text="Profile for alice")
        result = check_profile("alice", "Example", self.site)
        self.assertEqual(result["status"], "possible_match")

    @patch("profil3r.public_profiles.requests.get")
    def test_200_without_evidence_is_unknown(self, get):
        get.return_value = Mock(status_code=200, text="Generic homepage")
        self.assertEqual(check_profile("alice", "Example", self.site)["status"], "unknown")

    @patch("profil3r.public_profiles.requests.get")
    def test_not_found_text_overrides_positive(self, get):
        get.return_value = Mock(status_code=200, text="Profile for - No such user")
        self.assertEqual(check_profile("alice", "Example", self.site)["status"], "not_found")

    @patch("profil3r.public_profiles.requests.get")
    def test_404(self, get):
        get.return_value = Mock(status_code=404, text="")
        self.assertEqual(check_profile("alice", "Example", self.site)["status"], "not_found")

    @patch("profil3r.public_profiles.check_profile")
    def test_deduplicates_usernames(self, check):
        check.return_value = {"status": "unknown"}
        results = scan_public_profiles(["alice", "alice"], {"Example": self.site}, workers=1)
        self.assertEqual(len(results), 1)


if __name__ == "__main__":
    unittest.main()
