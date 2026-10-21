"""Offline request-contract, corpus coverage and classification regressions."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from profil3r.site_probe import (load_definitions, classify, declarative_request,
                                probe_site, scan_definitions, is_adult)
from profil3r.site_handlers import run_handler
from profil3r.modules.porn.onlyfans import Onlyfans
from profil3r.suite import inspect_usernames, main


def response(code=200, body="", url="https://example.org/users/alice", data=None):
    return Mock(status_code=code, text=body, url=url, headers={}, json=Mock(return_value=data))


class NativeProbeTests(unittest.TestCase):
    def test_entire_corpus_retained(self):
        sites = load_definitions()
        self.assertEqual(len(sites), 5360)
        self.assertEqual(len(load_definitions("username-url")), 5100)
        self.assertEqual(len(load_definitions("email-existence")), 260)
        self.assertEqual({d.get("handler") for d in sites.values() if d.get("handler")},
                         {"control_email", "office365", "okcupid", "adobe_recovery", "odnoklassniki_recovery"})
        self.assertEqual(sum(is_adult(d) for d in load_definitions("username-url").values()), 59)

    def test_message_and_tags_rules(self):
        for kind in ("message", "tags"):
            d = {"checkType": kind, "presenseStrs": ["User", "Profile"], "absenceStrs": ["not here"]}
            self.assertEqual(classify(d, response(body="User Profile"))[0], "possible_match")
            self.assertEqual(classify(d, response(body="User Profile not here"))[0], "not_found")
            self.assertEqual(classify(d, response(body="User"))[0], "unknown")
            self.assertEqual(classify({"checkType": kind, "absenceStrs": ["missing"]}, response())[0], "unknown")

    def test_blocked_and_error_pages_never_matches(self):
        d = {"e_code": 200, "m_code": 404, "e_string": "Profile"}
        for reply in (response(429, "Profile"), response(503, "Profile"), response(body="Profile cf-chl-"), response(403, "Profile")):
            self.assertNotEqual(classify(d, reply)[0], "possible_match")
        self.assertEqual(classify({"errors": {"Login wall": "Login required"}}, response(body="Login wall"))[0], "unknown")

    def test_two_marker_overlap_and_conflict(self):
        d = {"e_code": 200, "m_code": 200, "e_string": '"userId":', "m_string": '"userId":0'}
        self.assertEqual(classify(d, response(body='{"userId":0}'))[0], "not_found")
        self.assertEqual(classify(d, response(body='{"userId":10}'))[0], "possible_match")
        d.update(e_string="exists", m_string="absent")
        self.assertEqual(classify(d, response(body="exists absent"))[0], "unknown")

    def test_status_and_response_url_rules(self):
        self.assertEqual(classify({"checkType": "status_code"}, response(body="x" * 600))[0], "possible_match")
        self.assertEqual(classify({"checkType": "status_code"}, response(body="OK"))[0], "unknown")
        d = {"checkType": "response_url", "errorUrl": "/missing", "urlMain": "https://example.org"}
        self.assertEqual(classify(d, response(url="https://example.org/missing"))[0], "not_found")
        self.assertEqual(classify(d, response(url="https://example.org/"))[0], "unknown")
        self.assertEqual(classify(d, response(url="https://login.other.org/alice"))[0], "unknown")
        self.assertEqual(classify(d, response())[0], "possible_match")

    def test_post_json_and_form_preserve_identifier(self):
        for body_type, key in (("json", "json"), ("form", "data")):
            session = Mock()
            session.request.return_value = response(body="taken")
            d = {"check_type": "email-existence", "uri_check": "https://example.org/?e={email}",
                 "requestMethod": "POST", "requestPayload": {"email": "{email}"}, "body_type": body_type,
                 "e_code": 200, "m_code": 404, "e_string": "taken"}
            declarative_request(session, d, "a+b@example.org", 3)
            args, kwargs = session.request.call_args
            self.assertEqual(args[1], "https://example.org/?e=a%2Bb%40example.org")
            self.assertEqual(kwargs[key], {"email": "a+b@example.org"})
            self.assertEqual(kwargs["timeout"], 3)

    def test_precheck_cookie_csrf_regex_and_same_session(self):
        session = Mock(cookies=requests.cookies.cookiejar_from_dict({"csrftoken": "cookie-token"}))
        session.request.side_effect = [response(body='<meta name="csrf-token" content="csrf"><input name="nonce" value="abc">'), response(404)]
        d = {"check_type": "email-existence", "uri_check": "https://example.org/{nonce}",
             "headers": {"X-CSRF": "{csrf_token}", "X-Cookie": "{csrftoken_value}"},
             "pre_check": {"url": "https://example.org/login", "extract_csrf": "meta[name='csrf-token']",
                           "extract_regex": {"nonce": 'name="nonce" value="([^"]+)"'}}}
        declarative_request(session, d, "me@example.org", 3)
        self.assertEqual(session.request.call_args.args[1], "https://example.org/abc")
        self.assertEqual(session.request.call_args.kwargs["headers"]["X-CSRF"], "csrf")

    @patch("profil3r.site_probe.requests.Session")
    def test_skipped_definitions_and_bad_handles_make_no_request(self, session):
        for d, value in (({"disabled": True}, "alice"), ({"regexCheck": "[a-z]+"}, "alice!"),
                         ({"flow": "password-recovery"}, "alice"), ({}, "me@example.org")):
            result = probe_site(value, "example", {"check_type": "username-url", **d})
            self.assertEqual(result["status"], "skipped")
            self.assertFalse(result["attempted"])
        session.assert_not_called()
        self.assertEqual(result["url"], "")

    @patch("profil3r.site_probe.requests.Session")
    def test_full_corpus_produces_one_result_per_definition_offline(self, session):
        fake = session.return_value.__enter__.return_value
        fake.cookies = requests.cookies.cookiejar_from_dict({})
        fake.request.return_value = response(503, "Unavailable")
        fake.get.return_value = response(503, "Unavailable")
        fake.post.return_value = response(503, "Unavailable", data={})
        for kind, value in (("username-url", "exampleuser"), ("email-existence", "me@example.org")):
            sites = load_definitions(kind)
            results = scan_definitions([value], sites, workers=4, include_recovery=True)
            self.assertEqual({x["site"] for x in results}, set(sites))
            self.assertTrue(all(x["status"] != "possible_match" for x in results))

    @patch("profil3r.site_probe.requests.Session")
    def test_timeout_does_not_break_batch(self, session):
        session.return_value.__enter__.return_value.request.side_effect = requests.Timeout()
        results = scan_definitions(["alice"], {"a": {"check_type": "username-url", "uri_check": "https://example.org/{username}"}})
        self.assertEqual(results[0]["status"], "error")

    def test_username_entrypoints_reject_email(self):
        with self.assertRaises(ValueError):
            inspect_usernames(["me@example.org"], None, 4)
        module = Onlyfans({}, ["me@example.org", "Alice"])
        self.assertEqual(module.possible_usernames(), ["https://onlyfans.com/alice"])

    @patch("profil3r.site_probe.requests.Session")
    def test_onlyfans_email_never_makes_profile_request(self, session):
        results = Onlyfans({}, ["me@example.org"]).search()
        self.assertEqual(results["checked"], 0)
        self.assertEqual(results["accounts"], [])
        session.assert_not_called()

    def test_onlyfans_requires_matching_profile_object(self):
        d = {"domain": "onlyfans.com", "checkType": "status_code"}
        self.assertEqual(classify(d, response(body="x" * 1000, url="https://onlyfans.com/api2/v2/users/alice", data={}))[0], "unknown")
        self.assertEqual(classify(d, response(url="https://onlyfans.com/api2/v2/users/alice", data={"id": 123, "username": "alice"}))[0], "possible_match")
        self.assertEqual(classify(d, response(url="https://onlyfans.com/api2/v2/users/alice", data={"id": 123, "username": "bob"}))[0], "unknown")

    @patch("profil3r.suite.inspect_email_sites", return_value=[{"type": "email_site", "status": "unknown"}])
    @patch("profil3r.suite.inspect_email", return_value=[])
    def test_suite_email_uses_native_scanner_by_default(self, email, sites):
        with tempfile.TemporaryDirectory() as folder:
            main(["--email", "me@example.org", "--output", str(Path(folder) / "report.json")])
        sites.assert_called_once_with("me@example.org", 4, 8, False)

    def test_control_handler_rejects_uniform_taken_responses(self):
        session = Mock()
        session.request.return_value = response(body="taken")
        d = {"handler": "control_email", "check_type": "email-existence", "uri_check": "https://example.org/{email}",
             "e_code": 200, "m_code": 200, "e_string": "taken", "m_string": "available"}
        self.assertEqual(run_handler(session, d, "me@example.org", 3)[0], "unknown")

    def test_custom_handlers_unexpected_responses_stay_unknown(self):
        session = Mock()
        session.get.return_value = response(503)
        session.post.return_value = response(503, data={})
        for handler in ("office365", "adobe_recovery", "odnoklassniki_recovery", "okcupid"):
            self.assertEqual(run_handler(session, {"handler": handler}, "me@example.org", 3)[0], "unknown")


if __name__ == "__main__":
    unittest.main()
