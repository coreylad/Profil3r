# Profil3r — OSINT Toolkit

Profil3r examines supplied email addresses, public usernames, domains and telephone
numbering metadata. A profile match is a lead, not proof of identity or account ownership.

## Install or update

Python 3.9+ is required. Use a virtual environment on Ubuntu/Debian:

```bash
git clone https://github.com/coreylad/Profil3r.git
cd Profil3r
git switch develop/modernization-overhaul
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
```

For an existing checkout on that branch:

```bash
git pull --ff-only
python -m pip install --upgrade .
```

## Native MailAccess definitions

The complete bundled [MailAccess](https://github.com/KatrielMoses/MailAccess)
corpus contains **5,360 definitions** (the upstream metadata's 5,365 count is stale).
Profil3r runs these definitions directly. No MailAccess installation, CLI or subprocess
is required. The upstream MIT attribution is retained in `MAILACCESS-LICENSE`.

| Definition type | Total | Enabled upstream | Disabled upstream |
| --- | ---: | ---: | ---: |
| Username URL | 5,100 | 4,510 | 590 |
| Email existence | 260 | 214 | 46 |

Username scans include adult sites automatically: 59 adult username definitions,
53 enabled upstream. Disabled sites remain in reports as `skipped`, with reasons.
These are definition counts, not a claim that every live website currently works.
Username format restrictions may skip additional sites for a particular handle.

The native engine handles HTTP status rules, presence/absence messages, response-URL
rules, paired existence/absence markers, GET/HEAD/POST, form/JSON bodies, custom headers,
username regular expressions and character stripping, and session bootstrap cookies,
CSRF fields and named regex tokens. Native handlers cover the corpus's control-email,
Office365, Adobe, OK.ru and OkCupid flows. Unexpected provider responses stay inconclusive.
Rate limits, blocked pages and conflicting signals never become confirmed accounts.

## Run scans

```bash
# Email syntax, MX and native email-site definitions
profil3r suite --email "me@example.com"

# A single positional email also routes to email mode, never username URLs
profil3r "me@example.com"

# Every bundled username definition, including adult profiles
profil3r suite --username "exampleuser,example_user" --workers 8

# Standard name permutations also use the bundled username corpus
profil3r john doe

# All bundled adult username definitions only
profil3r --adult-usernames "exampleuser"

# Recovery flows are opt-in because providers may send notifications
profil3r suite --email "me@example.com" --include-recovery

# Email syntax and MX only
profil3r suite --email "me@example.com" --dns-only

# Public MX, SPF and DMARC
profil3r suite --domain example.com

# Phone metadata, not subscriber identity
profil3r suite --phone "+442071838750" --region GB

# CSV includes skipped, unknown, error and rate-limit outcomes
profil3r suite --username "exampleuser" --format csv --output reports/usernames.csv

# Guided menu
profil3r wizard
```

`--mailaccess` remains a compatibility alias for native email checks. It no longer
launches the upstream program. `--timeout` sets the per-request timeout (default
8 seconds, maximum 120); `--workers` accepts 1–16 concurrent probes. A scan of thousands
of sites can take a long time. There is no implicit 334-site or 700-site limit.

Scans print live progress as each definition finishes: completed/total, percentage,
elapsed seconds, site, status, HTTP code and reason. A waiting message appears every
five seconds without a completion, and a final summary separates attempted requests
from skipped definitions. Output is flushed immediately, including when redirected.

Final results have separate **General** and **Porn / adult sites** sections. Adult-site
rows carry a `[PORN/ADULT]` label in live output. JSON and CSV retain the `adult`,
`section` and `category_note` fields; JSON also contains section counts. These labels
describe the website category and do not establish account ownership.

The name scan runs at most 50 generated handles and reports the number of omitted
permutations. Explicit username scans accept at most 50 distinct handles. Email addresses
are rejected in username mode; the tool never assumes an email's local part is a handle.

OnlyFans requires an explicit public handle. Its native check requires a matching
profile JSON object; a generic HTTP 200 or frontend page is not account evidence.
OnlyFans signing rules and bot protections can expire or block the bundled endpoint;
those responses are reported as unknown/error rather than fabricated profile matches.

Suite reports default to `reports/osint.json`, overwritten by the next run. Use
`--output` for separate reports. JSON and CSV retain site identifiers, status, reason,
adult/category labels and whether a request was attempted. Status-code and absence-only
rules can produce false positives; every positive is labeled `possible_match`.

## Custom public profile definitions

`--sites custom.json` accepts the original `websites` mapping, with HTTPS URLs containing
`{username}` and `check_text` / `not_found_text` arrays. The bundled corpus lives in
`profil3r/mailaccess_sites.json` and uses the native MailAccess schema. These are separate
formats. `--adult-sites custom.json` overrides the adult-only selection with custom sites.

## Optional breach checks

```bash
export HIBP_API_KEY="your-api-key"
profil3r suite --email "me@example.com" --breaches
```

HIBP results are breach associations, not account confirmation. Sensitive breaches may
be withheld by the provider. Phone metadata cannot identify a subscriber or live location.
Use identifiers you own or are authorized to assess; keep reports out of source control.

## Validation

```bash
python -m compileall -q profil3r
python -m unittest discover -s tests -v
```

Tests mock network responses, including a full-corpus dispatch check. They verify schema
integration and failure handling, not current live availability of every provider.
