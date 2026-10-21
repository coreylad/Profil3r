"""Command line interface for Profil3r."""
import argparse
import os
from pathlib import Path

from profil3r.core import Core, check_self_email_exposure
from profil3r.public_profiles import load_sites, scan_public_profiles
import json
import sys


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if argv and argv[0] in ("suite", "wizard"):
        from profil3r.suite import main as suite_main
        return suite_main(["--interactive"] + argv[1:] if argv[0] == "wizard" else argv[1:])
    parser = argparse.ArgumentParser(description="Public-profile discovery and opt-in email breach checks")
    parser.add_argument("names", nargs="*", help="Name components to search")
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parent.parent / "config.json")
    parser.add_argument("--format", choices=["json", "csv"], default="json")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--self-email", metavar="ADDRESS", help="Check your own email for known adult-site breach exposure")
    parser.add_argument("--adult-usernames", metavar="NAMES", help="Comma-separated usernames to check on public adult profiles")
    parser.add_argument("--adult-sites", type=Path, default=Path(__file__).resolve().parent.parent / "public_adult_sites.json")
    args = parser.parse_args(argv)
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if args.adult_usernames:
        if args.names or args.self_email:
            parser.error("--adult-usernames cannot be combined with other scan modes")
        try:
            sites = load_sites(args.adult_sites)
            results = scan_public_profiles(args.adult_usernames.split(","), sites, workers=args.workers)
        except (OSError, ValueError) as exc:
            parser.exit(1, "Public profile check: {}\\n".format(exc))
        print(json.dumps(results, indent=2))
        return
    if args.self_email:
        if args.names:
            parser.error("--self-email cannot be combined with name searches")
        key = os.environ.get("HIBP_API_KEY")
        if not key:
            parser.error("Set HIBP_API_KEY in your environment (never pass the key on the command line)")
        try:
            matches = check_self_email_exposure(args.self_email, key)
        except (ValueError, RuntimeError) as exc:
            parser.exit(1, "Email exposure check: {}\n".format(exc))
        if not matches:
            print("No matching adult-platform breaches returned. This does not establish account absence.")
        for match in matches:
            print("{} | {} | {}".format(match["name"], match["breach_date"], match["domain"]))
        return
    if not args.names:
        parser.error("Provide name components or use --self-email")
    try:
        scanner = Core(args.config, args.names, report_format=args.format, workers=args.workers)
        scanner.get_permutations()
        report = scanner.run()
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, "Profil3r: {}\n".format(exc))
    print("Report saved to {}".format(report))


if __name__ == "__main__":
    main()
