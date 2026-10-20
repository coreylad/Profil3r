"""Command line interface for Profil3r."""
import argparse
from pathlib import Path
import sys

from profil3r.core import Core


def main(argv=None):
    parser = argparse.ArgumentParser(description="Search public profiles for name permutations")
    parser.add_argument("names", nargs="+", help="Name components to search")
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parent.parent / "config.json")
    parser.add_argument("--format", choices=["json", "csv"], default="json")
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args(argv)
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    try:
        scanner = Core(args.config, args.names, report_format=args.format, workers=args.workers)
        scanner.get_permutations()
        report = scanner.run()
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, "Profil3r: {}\n".format(exc))
    print("Report saved to {}".format(report))


if __name__ == "__main__":
    main()
