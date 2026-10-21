"""Guided, evidence-first OSINT for user-provided identifiers.

Does not enumerate private account registration, bypass access controls or infer
identity from a public username match.
"""
import argparse
import csv
from datetime import datetime, timezone
from email.utils import parseaddr
import json
import os
from pathlib import Path
import re

from profil3r.public_profiles import load_sites, scan_public_profiles
from profil3r.core import check_self_email_exposure


def inspect_email(value, breach_check=False):
    value = value.strip()
    _, parsed = parseaddr(value)
    if parsed != value or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
        raise ValueError("Invalid email address")
    domain = value.rsplit("@", 1)[1].lower()
    findings = [{"type": "email", "value": value, "status": "syntax_valid",
                 "note": "Valid syntax is not proof of mailbox existence"}]
    try:
        import dns.resolver
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        mx = sorted(str(item.exchange).rstrip(".") for item in answers)
        findings.append({"type": "mail_domain", "value": domain,
                         "status": "mx_found", "mx_hosts": mx})
    except Exception as exc:
        findings.append({"type": "mail_domain", "value": domain,
                         "status": "unverified", "detail": type(exc).__name__})
    if breach_check:
        key = os.getenv("HIBP_API_KEY")
        if not key:
            findings.append({"type": "breach", "status": "skipped",
                             "detail": "HIBP_API_KEY not set"})
        else:
            try:
                for match in check_self_email_exposure(value, key):
                    findings.append({"type": "breach", **match})
            except RuntimeError as exc:
                findings.append({"type": "breach", "status": "error", "detail": str(exc)})
    return findings


def inspect_phone(value, region="US"):
    try:
        import phonenumbers
    except ImportError as exc:
        raise RuntimeError("Install phonenumbers to enable phone analysis") from exc
    from phonenumbers import carrier, geocoder, timezone as phone_timezone
    try:
        parsed = phonenumbers.parse(value, region.upper())
    except phonenumbers.NumberParseException as exc:
        raise ValueError("Cannot parse phone number: {}".format(exc)) from exc
    valid = phonenumbers.is_valid_number(parsed)
    return [{
        "type": "phone", "value": value,
        "status": "valid_numbering_plan" if valid else "invalid_or_unallocated",
        "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
        "possible": phonenumbers.is_possible_number(parsed),
        "region": phonenumbers.region_code_for_number(parsed),
        "number_type": str(phonenumbers.number_type(parsed)),
        "carrier_hint": carrier.name_for_number(parsed, "en"),
        "geography_hint": geocoder.description_for_number(parsed, "en"),
        "timezones": list(phone_timezone.time_zones_for_number(parsed)),
        "note": "Metadata does not reveal subscriber identity, live location or current carrier",
    }]


def inspect_usernames(values, sites_path, workers):
    sites = load_sites(sites_path)
    return [{"type": "public_profile", **item} for item in
            scan_public_profiles(values, sites, workers=workers)]


def save_report(findings, output, format_name):
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {"generated_at": datetime.now(timezone.utc).isoformat(),
              "disclaimer": "Possible matches are not verified identities or private account membership.",
              "findings": findings}
    if format_name == "json":
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    elif format_name == "csv":
        fields = ["type", "value", "site", "url", "status", "detail", "e164",
                  "region", "domain", "name", "breach_date", "source", "note"]
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(findings)
    else:
        raise ValueError("Unsupported report format")
    return path


def wizard():
    print("\nProfil3r — guided OSINT suite")
    print("Only investigate identifiers you own or are authorized to assess.")
    print("1. Email: syntax, MX records, optional self-email breach exposure")
    print("2. Username: public profile checks (not account ownership)")
    print("3. Telephone: numbering plan and public metadata (not subscriber lookup)")
    choice = input("Select 1, 2 or 3: ").strip()
    if choice == "1":
        value = input("Email address: ").strip()
        consent = input("Check your own email against HIBP? [y/N]: ").strip().lower() == "y"
        return "email", value, consent
    if choice == "2":
        return "username", input("Username(s), comma-separated: ").strip(), False
    if choice == "3":
        return "phone", input("Phone number including country code if possible: ").strip(), False
    raise ValueError("Choose 1, 2 or 3")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="profil3r suite",
        description="Guided email, public username and phone OSINT with evidence-based reports",
        epilog="Examples: profil3r suite --interactive | profil3r suite --email me@example.com | profil3r suite --phone '+442071838750' --region GB",
    )
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--email", help="Email syntax and domain MX; does not enumerate accounts")
    target.add_argument("--username", help="One or more comma-separated public usernames")
    target.add_argument("--phone", help="Phone number to parse and inspect")
    target.add_argument("--interactive", action="store_true", help="Step-by-step guided menu")
    parser.add_argument("--region", default="US", help="Default region for national phone numbers (e.g. GB, US)")
    parser.add_argument("--breaches", action="store_true", help="Opt-in HIBP adult breach lookup for your own email; needs HIBP_API_KEY")
    parser.add_argument("--sites", type=Path, default=Path(__file__).resolve().parent / "public_adult_sites.json")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--format", choices=["json", "csv"], default="json")
    parser.add_argument("--output", type=Path, help="Report path; defaults to reports/osint.<format>")
    args = parser.parse_args(argv)
    if not 1 <= args.workers <= 16:
        parser.error("--workers must be 1 to 16")
    if args.breaches and not args.email:
        parser.error("--breaches requires --email")
    try:
        if args.interactive or not any((args.email, args.username, args.phone)):
            mode, value, breach = wizard()
        else:
            mode = "email" if args.email else "username" if args.username else "phone"
            value = args.email or args.username or args.phone
            breach = args.breaches
        if mode == "email":
            findings = inspect_email(value, breach)
        elif mode == "username":
            findings = inspect_usernames(value.split(","), args.sites, args.workers)
        else:
            findings = inspect_phone(value, args.region)
        print("\nResults:")
        for item in findings:
            print("  {}: {} ({})".format(item.get("type", "finding"),
                                        item.get("site", item.get("value", "")),
                                        item.get("status", "unknown")))
        path = save_report(findings, args.output or Path("reports/osint." + args.format), args.format)
        print("\nSaved report: {}".format(path))
        print("Reminder: a possible public match does not confirm account ownership.")
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, "Profil3r suite: {}\n".format(exc))


if __name__ == "__main__":
    main()
