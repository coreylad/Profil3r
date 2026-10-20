"""Command line interface for Profil3r."""
import argparse
import os
from pathlib import Path

from profil3r.core import Core, check_self_email_exposure


def main(argv=None):
    parser = argparse.ArgumentParser(description="Public-profile discovery and opt-in email breach checks")
    parser.add_argument("names", nargs="*", help="Name components to search")
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parent.parent / "config.json")
    parser.add_argument("--format", choices=["json", "csv"], default="json")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--self-email", metavar="ADDRESS", help="Check your own email for known adult-site breach exposure")
    args = parser.parse_args(argv)
    if args.workers < 1:
        parser.error("--workers must be at least 1")
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
