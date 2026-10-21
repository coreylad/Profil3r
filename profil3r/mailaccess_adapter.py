"""Compatibility API for native bundled email checks; no subprocess required."""
from profil3r.site_probe import load_definitions, scan_definitions


def investigate_with_mailaccess(email, timeout=8, workers=4, include_recovery=False):
    if email.count("@") != 1:
        raise ValueError("Provide an email address")
    findings = scan_definitions([email], load_definitions("email-existence"), workers,
                               timeout, include_recovery)
    return {"type": "mailaccess", "status": "completed", "engine": "profil3r-native",
            "report": {"findings": findings}}
