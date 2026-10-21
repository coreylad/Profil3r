# Profil3r — OSINT Toolkit

Profil3r is a command-line OSINT toolkit for examining user-provided email addresses,
public usernames and telephone numbering metadata. **A public profile match does not
establish identity, and a breach association does not establish a current account.**

## Install

Python 3.9+ is required. On Ubuntu/Debian, use a virtual environment to avoid
the externally-managed Python installation restriction:

```bash
git clone https://github.com/coreylad/Profil3r.git
cd Profil3r
git switch develop/modernization-overhaul
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

## Guided menu

```bash
profil3r suite --interactive
# or
profil3r wizard
```

The menu guides you through choosing email, username or phone checks, entering
an identifier and writing a report.

## Command-line examples

```bash
# Email syntax and public mail-domain records (no mailbox enumeration)
profil3r suite --email "me@example.com"

# Optional adult-platform breach associations for your OWN email
export HIBP_API_KEY="your-api-key"
profil3r suite --email "me@example.com" --breaches

# Public profile username checks
profil3r suite --username "exampleuser,example_user"

# Phone numbering plan, country, carrier/geography hints (not owner lookup)
profil3r suite --phone "+442071838750" --region GB

# CSV output
profil3r suite --username "exampleuser" --format csv --output reports/usernames.csv

# Previous name-based workflow remains available
profil3r john doe
```

The suite defaults to `reports/osint.json` (overwritten on the next run).
Use `--output` to preserve each investigation. **Reports may contain sensitive
identifiers: store them securely and do not commit them to Git.**

## Public profile definitions

Site definitions live in `profil3r/public_adult_sites.json`.
Each site provides an HTTPS public profile URL containing `{username}`,
plus optional `check_text` and `not_found_text` arrays.
You can provide a custom definition file with `--sites my_sites.json`.
Current starter definitions cover Pornhub and OnlyFans; site-specific positive
indicators have not been verified. HTTP 200 alone is **never** a match.

## Important limitations

- The tool does not query private account registration or password-reset endpoints.
- Email checks do not establish whether an inbox exists. HIBP requires an API key,
  and sensitive breaches may be omitted by the provider.
- Phone metadata does not establish subscriber identity, live location or current
  carrier; portability can make carrier hints inaccurate.
- Public profile results are leads, not confirmed identity matches.
- Network checks can fail due to blocking, rate limits, or website changes.
- Run checks only for purposes you are authorized to investigate.

## Tests

```bash
python -m unittest discover -s tests
```

## Development status

The development branch is a work in progress; tests and live site rules require
validation before merging. The original project is MIT licensed.
