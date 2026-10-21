"""Public OnlyFans handle checks; an email address is never a profile handle."""
import re
from urllib.parse import quote

from profil3r.site_probe import load_definitions, scan_definitions


class Onlyfans:
    def __init__(self, config, permutations_list):
        # Do not guess a handle from an email local part or use a configurable
        # URL template to turn an arbitrary identifier into a reported account.
        self.permutations_list = list(dict.fromkeys(
            value.strip().lower() for value in permutations_list
            if re.fullmatch(r"[A-Za-z0-9_.-]+", value.strip())
        ))

    def possible_usernames(self):
        return ["https://onlyfans.com/" + quote(value, safe="") for value in self.permutations_list]

    def search(self):
        sites = {key: definition for key, definition in load_definitions("username-url").items()
                 if definition.get("domain", "").lower() in ("onlyfans.com", "www.onlyfans.com")}
        findings = scan_definitions(self.permutations_list, sites)
        return {"accounts": [{"value": item["url"], "status": item["status"]}
                             for item in findings if item["status"] == "possible_match"],
                "findings": findings, "checked": sum(item["attempted"] for item in findings)}
