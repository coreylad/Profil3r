"""Core orchestration and report generation."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from itertools import combinations, permutations
import csv
import json
from pathlib import Path
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
            {"name": "facebook", "method": self.facebook},
            {"name": "twitter", "method": self.twitter},
            {"name": "tiktok", "method": self.tiktok},
            {"name": "instagram", "method": self.instagram},
            {"name": "onlyfans", "method": self.onlyfans},
        ]

    def config(self):
        return self.CONFIG

    def get_permutations(self):
        tokens = [str(item).strip().lower() for item in self.items if str(item).strip()]
        tokens = list(dict.fromkeys(tokens))
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

    def print_results(self, element):
        accounts = self.results.get(element, {}).get("accounts", [])
        print("\n{}: {} results".format(element.upper(), len(accounts)))
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
                writer = csv.DictWriter(handle, fieldnames=["platform", "value", "breached"])
                writer.writeheader()
                for platform, payload in self.results.items():
                    for account in payload.get("accounts", []):
                        writer.writerow({"platform": platform, "value": account.get("value", ""), "breached": account.get("breached", "")})
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
