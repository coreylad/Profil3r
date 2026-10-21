"""Core orchestration and report generation."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import combinations, permutations
import csv
import json
from pathlib import Path

from profil3r.public_profiles import load_sites, scan_public_profiles
from profil3r.site_probe import load_definitions, scan_definitions, is_adult
import re

from profil3r.modules.email import email
from profil3r.modules.social import facebook, twitter, tiktok, instagram
from profil3r.modules.porn import onlyfans


class Core:
    def __init__(self, config_path, items, report_format="json", workers=4):
        with open(config_path, encoding="utf-8") as handle:
            self.CONFIG = json.load(handle)
        self.items = list(items)
        self.permutations_list = []
        self.results = {}
        self.report_format = report_format
        self.workers = max(1, int(workers))
        self.modules = [
            {"name": "email", "method": self.email},
            {"name": "public_profiles", "method": self.public_profiles},
        ]

    def config(self):
        return self.CONFIG

    def get_permutations(self):
        tokens = [str(item).strip().lower() for item in self.items if str(item).strip()]
        tokens = list(dict.fromkeys(tokens))
        if any("@" in token for token in tokens):
            raise ValueError("Name scans require names/handles, not email addresses; use profil3r suite --email")
        # Bound input size to avoid factorial memory exhaustion.
        if len(tokens) > 5:
            raise ValueError("At most five name components are supported")
        values = set()
        for count in range(1, len(tokens) + 1):
            for selection in combinations(tokens, count):
                for order in permutations(selection):
                    values.add("".join(order))
                    if count > 1:
                        values.add(".".join(order))
        self.permutations_list = sorted(values)
        return self.permutations_list

    def email(self):
        return email.Email(self.CONFIG, self.permutations_list).search()

    def facebook(self):
        return facebook.Facebook(self.CONFIG, self.permutations_list).search()

    def twitter(self):
        return twitter.Twitter(self.CONFIG, self.permutations_list).search()

    def tiktok(self):
        return tiktok.TikTok(self.CONFIG, self.permutations_list).search()

    def instagram(self):
        return instagram.Instagram(self.CONFIG, self.permutations_list).search()

    def onlyfans(self):
        return onlyfans.Onlyfans(self.CONFIG, self.permutations_list).search()

    def public_profiles(self, adult_only=False):
        """Run every bundled username definition, including adult platforms."""
        sites = load_definitions("username-url")
        if adult_only:
            sites = {key: definition for key, definition in sites.items() if is_adult(definition)}
        print("Scanning {} username definitions for {} handles (including adult sites).".format(
            len(sites), min(len(self.permutations_list), 50)), flush=True)
        findings = scan_definitions(self.permutations_list[:50], sites, workers=min(self.workers, 16))
        return {"accounts": [
            {"value": finding["url"], "status": finding["status"],
             "site": finding["site"], "http_status": finding.get("http_status")}
            for finding in findings if finding["status"] == "possible_match"
        ], "checked": sum(item["attempted"] for item in findings),
            "definitions": len(sites), "username_count": min(len(self.permutations_list), 50),
            "omitted_permutations": max(0, len(self.permutations_list) - 50),
            "status_counts": {status: sum(item["status"] == status for item in findings)
                              for status in ("possible_match", "not_found", "unknown", "error", "skipped", "rate_limited")},
            "findings": findings}

    def adult_public_profiles(self):
        return self.public_profiles(adult_only=True)

    def print_results(self, element):
        accounts = self.results.get(element, {}).get("accounts", [])
        print("\n{}: {} results".format(element.upper(), len(accounts)))
        if element in ("adult_public_profiles", "public_profiles"):
            print("  {} checks; statuses: {}".format(
                self.results[element].get("checked", 0),
                self.results[element].get("status_counts", {})))
        for account in accounts:
            label = account["value"]
            if element == "email":
                label += " [{}]".format("BREACH INDICATED" if account.get("breached") else "UNVERIFIED")
            print("  " + label)

    def generate_report(self):
        template = self.CONFIG.get("report_path", "./reports/{}.json")
        stem = "_".join(re.sub(r"[^a-zA-Z0-9_-]", "_", item) for item in self.items)
        path = Path(template.format(stem))
        if self.report_format == "csv":
            path = path.with_suffix(".csv")
        path.parent.mkdir(parents=True, exist_ok=True)
        if self.report_format == "csv":
            with path.open("w", newline="", encoding="utf-8") as handle:
                fields = ["platform", "value", "breached", "site", "url", "status", "detail",
                          "category", "adult", "attempted", "http_status"]
                writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                for platform, payload in self.results.items():
                    for finding in payload.get("findings", payload.get("accounts", [])):
                        writer.writerow({"platform": platform, **finding})
        else:
            with path.open("w", encoding="utf-8") as handle:
                json.dump(self.results, handle, indent=2)
        return path

    def run(self):
        with ThreadPoolExecutor(max_workers=self.workers) as executor:
            pending = {executor.submit(module["method"]): module["name"] for module in self.modules}
            for future in as_completed(pending):
                name = pending[future]
                try:
                    self.results[name] = future.result()
                except Exception as exc:
                    self.results[name] = {"accounts": [], "error": str(exc)}
                self.print_results(name)
        return self.generate_report()


# Curated identifiers, not a guess based on generic words in breach descriptions.
_ADULT_BREACH_IDENTIFIERS = {
    "adultfriendfinder", "ashleymadison", "brazzers", "youporn",
    "pornhub", "xhamster", "fling", "cam4",
}


def check_self_email_exposure(address, api_key):
    """Query HIBP's documented breached-account endpoint for a self-supplied address.

    Results are breach associations, not proof of a current or historical account.
    Sensitive breaches may be withheld by the upstream API.
    """
    from urllib.error import HTTPError, URLError
    from urllib.parse import quote
    from urllib.request import Request, urlopen

    if not address or "@" not in address or address.count("@") != 1:
        raise ValueError("Provide a valid email address")
    if not api_key:
        raise ValueError("HIBP_API_KEY is required")
    url = "https://haveibeenpwned.com/api/v3/breachedaccount/" + quote(address.strip(), safe="")
    request = Request(url + "?truncateResponse=false", headers={
        "hibp-api-key": api_key,
        "user-agent": "Profil3r-self-email-exposure/1.1",
        "accept": "application/json",
    })
    try:
        with urlopen(request, timeout=15) as response:
            breaches = json.load(response)
    except HTTPError as exc:
        if exc.code == 404:
            return []
        if exc.code in (401, 403):
            raise RuntimeError("HIBP denied access; verify API key and account permissions") from exc
        if exc.code == 429:
            raise RuntimeError("HIBP rate limit reached; retry later") from exc
        raise RuntimeError("HIBP returned HTTP {}".format(exc.code)) from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError("Could not complete HIBP request") from exc
    matches = []
    for breach in breaches:
        name = str(breach.get("Name", ""))
        domain = str(breach.get("Domain", ""))
        normalized = "".join(char for char in (name + domain).lower() if char.isalnum())
        if any(identifier in normalized for identifier in _ADULT_BREACH_IDENTIFIERS):
            matches.append({
                "name": name,
                "domain": domain,
                "breach_date": breach.get("BreachDate", "unknown"),
                "source": "Have I Been Pwned",
                "status": "breach_association_not_account_confirmation",
            })
    return matches
