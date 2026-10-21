"""Configurable checks of public profile pages, not private email membership."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote
import json
from pathlib import Path

import requests


def load_sites(path):
    with Path(path).open(encoding="utf-8") as handle:
        data = json.load(handle)
    sites = data.get("websites")
    if not isinstance(sites, dict):
        raise ValueError("Site definitions require a websites object")
    for name, site in sites.items():
        url = site.get("url", "")
        if not url.startswith("https://") or "{username}" not in url:
            raise ValueError("Invalid public profile URL for " + name)
    return sites


def check_profile(username, name, site, timeout=8):
    """Return evidence-based status; never infer a match from HTTP 200 alone."""
    if site.get("check_type") == "username-url":
        from profil3r.site_probe import probe_site
        return probe_site(username, name, site, timeout)
    if "@" in username:
        raise ValueError("Public profile checks require a username, not an email address")
    url = site["url"].replace("{username}", quote(username, safe=""))
    try:
        response = requests.get(
            url, timeout=timeout, allow_redirects=True,
            headers={"User-Agent": "Profil3r/1.1 public-profile-check"},
        )
    except requests.RequestException as exc:
        return {"site": name, "url": url, "status": "error", "detail": type(exc).__name__}
    if response.status_code == 404 or (site.get("missing_status") is not None and response.status_code == site["missing_status"] and site.get("expected_status") != response.status_code):
        status = "not_found"
    elif response.status_code != 200:
        status = "unknown"
    else:
        body = response.text.lower()
        positive = [term for term in site.get("check_text", []) if term.lower() in body]
        negative = [term for term in site.get("not_found_text", []) if term.lower() in body]
        if negative:
            status = "not_found"
        elif positive and (site.get("expected_status") is None or response.status_code == site["expected_status"]):
            status = "possible_match"
        else:
            status = "unknown"
    return {"site": name, "url": url, "status": status, "http_status": response.status_code}


def scan_public_profiles(usernames, sites, workers=4):
    if not 1 <= workers <= 16:
        raise ValueError("workers must be between 1 and 16")
    usernames = list(dict.fromkeys(u.strip() for u in usernames if u.strip()))
    if len(usernames) > 50:
        raise ValueError("At most 50 usernames per scan")
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(check_profile, username, name, site)
            for username in usernames for name, site in sites.items()
        ]
        return [future.result() for future in as_completed(futures)]


def load_mailaccess_username_sites(path=None, include_disabled=False):
    """Load native schema definitions without dropping message/URL/status rules."""
    from profil3r.site_probe import load_definitions
    return {key: definition for key, definition in load_definitions("username-url", path).items()
            if include_disabled or not definition.get("disabled")}
