"""Native MailAccess-schema probes; no upstream program is required."""
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from html import unescape
from html.parser import HTMLParser
import json
from pathlib import Path
import re
from urllib.parse import quote, urlparse

import requests

CORPUS = Path(__file__).with_name("mailaccess_sites.json")
_BLOCK_MARKERS = ("cf-chl-", "just a moment...", "verify you are human",
                  "access denied", "checking your browser", "captcha challenge")


def load_definitions(check_type=None, path=None):
    with Path(path or CORPUS).open(encoding="utf-8") as handle:
        sites = json.load(handle).get("sites")
    if not isinstance(sites, dict):
        raise ValueError("Corpus requires a sites object")
    return {key: value for key, value in sites.items()
            if check_type is None or value.get("check_type") == check_type}


def is_adult(definition):
    labels = [definition.get("category", ""), *definition.get("tags", [])]
    return any(any(term in str(label).lower() for term in ("nsfw", "adult", "porn")) for label in labels)


def substitute(value, tokens, encoded=False):
    if isinstance(value, dict):
        return {key: substitute(item, tokens, encoded) for key, item in value.items()}
    if isinstance(value, list):
        return [substitute(item, tokens, encoded) for item in value]
    if isinstance(value, str):
        for key, item in tokens.items():
            value = value.replace("{" + key + "}", quote(str(item), safe="") if encoded else str(item))
    return value


def _markers(value):
    if isinstance(value, str):
        return [value] if value else []
    return [str(item) for item in (value or []) if item]


def classify(definition, response):
    """Preserve uncertainty when signals conflict or a provider blocks requests."""
    code, body = response.status_code, unescape(response.text or "")
    if code == 429:
        return "rate_limited", "HTTP 429"
    if code >= 500:
        return "unknown", "Provider server error"
    if any(marker.lower() in body.lower() for marker in _markers(definition.get("rate_limited_strings"))):
        return "rate_limited", "Provider rate-limit marker"
    if any(marker in body.lower() for marker in _BLOCK_MARKERS):
        return "unknown", "Challenge or access-block page"
    for marker in definition.get("errors") or {}:
        if str(marker) in body:
            return "unknown", str(definition["errors"][marker])
    if code in (401, 403):
        return "unknown", "Access restricted"
    if "e_code" in definition and "m_code" in definition:
        positive, negative = str(definition.get("e_string") or ""), str(definition.get("m_string") or "")
        hit = code == definition["e_code"] and (not positive or positive in body)
        miss = code == definition["m_code"] and (not negative or negative in body)
        if hit and miss:
            if negative and (not positive or positive in negative):
                return "not_found", "Absence marker"
            if positive and (not negative or negative in positive):
                return "possible_match", "Presence marker"
            return "unknown", "Conflicting existence and absence signals"
        if hit:
            return "possible_match", "Existence status and marker"
        if miss:
            return "not_found", "Absence status and marker"
        return "unknown", "No matching existence or absence rule"
    if definition.get("domain") in ("onlyfans.com", "www.onlyfans.com") and code == 200:
        try:
            data = response.json()
        except ValueError:
            return "unknown", "OnlyFans did not return profile JSON"
        expected = urlparse(str(response.url)).path.rstrip("/").rsplit("/", 1)[-1]
        if isinstance(data, dict) and data.get("id") and str(data.get("username", "")).lower() == expected.lower():
            return "possible_match", "OnlyFans profile JSON matches the requested handle"
        return "unknown", "OnlyFans returned no matching profile object"
    kind = definition.get("checkType", "status_code")
    if code in (404, 410):
        return "not_found", "HTTP {}".format(code)
    if kind in ("message", "tags", "status_code"):
        if not 200 <= code < 300:
            return "unknown", "Unexpected HTTP status"
        if any(marker in body for marker in _markers(definition.get("absenceStrs"))):
            return "not_found", "Absence marker"
        positive = _markers(definition.get("presenseStrs"))
        if positive:
            return (("possible_match", "Presence markers") if all(marker in body for marker in positive)
                    else ("unknown", "Presence markers not satisfied"))
        if kind in ("message", "tags"):
            if body.strip() and _markers(definition.get("absenceStrs")):
                return "possible_match", "Nonempty response without configured absence markers"
            return "unknown", "No usable body signal"
        if code == 200 and len(body) >= int(definition.get("min_response_bytes", 500)):
            return "possible_match", "Configured status-code rule; unverified profile"
        return "unknown", "Insufficient response for status-code rule"
    if kind == "response_url":
        final = str(response.url)
        if definition.get("errorUrl") and definition["errorUrl"] in final:
            return "not_found", "Redirected to configured error URL"
        main = urlparse(definition.get("urlMain") or definition.get("url") or "")
        actual = urlparse(final)
        if actual.hostname and main.hostname and actual.hostname.removeprefix("www.") != main.hostname.removeprefix("www."):
            return "unknown", "Redirected to another domain"
        if actual.path in ("", "/", "/404"):
            return "unknown", "Redirect is not a user-specific profile"
        if code == 200:
            return "possible_match", "Configured response-URL rule"
    return "unknown", "Unsupported or inconclusive detection rule"


class _TokenParser(HTMLParser):
    def __init__(self, selector):
        super().__init__()
        match = re.search(r"(meta|input)\s*\[name=['\"]([^'\"]+)['\"]\]", selector)
        if not match:
            raise ValueError("Unsupported CSRF selector")
        self.tag, self.name = match.groups()
        self.value = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == self.tag and attrs.get("name") == self.name:
            self.value = attrs.get("content" if tag == "meta" else "value")


def bootstrap(session, config, tokens, timeout):
    response = session.request(config.get("method", "GET"), substitute(config["url"], tokens, True),
                               headers=substitute(config.get("headers", {}), tokens),
                               timeout=timeout, allow_redirects=True)
    if response.status_code != 200:
        raise ValueError("Session bootstrap returned HTTP {}".format(response.status_code))
    for key, value in session.cookies.items():
        tokens[key + "_value"] = value
    csrf = None
    if config.get("extract_csrf"):
        parser = _TokenParser(config["extract_csrf"])
        parser.feed(response.text)
        csrf = parser.value
        if not csrf:
            raise ValueError("Session bootstrap did not provide CSRF token")
    if not csrf:
        csrf = session.cookies.get(config.get("cookie_name", "csrftoken"))
    if csrf:
        tokens.update(csrf_token=csrf, csrftoken_value=csrf)
    for name, pattern in config.get("extract_regex", {}).items():
        match = re.search(pattern, response.text)
        if not match:
            raise ValueError("Session bootstrap missing token: " + name)
        tokens[name] = match.group(1) if match.groups() else match.group(0)


def declarative_request(session, definition, value, timeout):
    kind = "email" if definition["check_type"] == "email-existence" else "username"
    if kind == "username":
        for char in definition.get("strip_bad_char", ""):
            value = value.replace(char, "")
    tokens = {kind: value}
    if definition.get("pre_check"):
        bootstrap(session, definition["pre_check"], tokens, timeout)
    url = substitute(definition.get("uri_check") or definition.get("url", ""), tokens, True)
    headers = substitute(definition.get("headers", {}), tokens)
    payload = substitute(definition.get("requestPayload"), tokens)
    if any(re.search(r"\{[A-Za-z_][A-Za-z_0-9]*\}", str(item)) for item in (url, headers, payload)):
        raise ValueError("Unresolved request template token")
    if not url.startswith(("https://", "http://")):
        raise ValueError("No supported probe URL")
    kwargs = {"headers": {"User-Agent": "Profil3r/1.2 native-site-probe", **headers},
              "timeout": timeout, "allow_redirects": definition.get("follow_redirects", True)}
    if payload is not None:
        content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
        body_type = definition.get("body_type")
        key = "json" if isinstance(payload, (dict, list)) and body_type != "form" and (body_type == "json" or "application/json" in content_type) else "data"
        kwargs[key] = payload
    method = definition.get("requestMethod", "HEAD" if definition.get("requestHeadOnly") else "GET").upper()
    if method not in ("GET", "HEAD", "POST"):
        raise ValueError("Unsupported request method: " + method)
    response = session.request(method, url, **kwargs)
    prepared = substitute(definition, tokens)
    if definition.get("errorUrl"):
        prepared["errorUrl"] = substitute(definition["errorUrl"], tokens, True)
    return response, classify(prepared, response)


def probe_site(value, identifier, definition, timeout=8, include_recovery=False):
    if definition.get("check_type") == "username-url" and "@" in value:
        return {"site": identifier, "value": value, "url": "",
                "check_type": "username-url", "adult": is_adult(definition),
                "status": "skipped", "attempted": False,
                "detail": "Email addresses cannot be used as profile usernames"}
    result = {"site": identifier, "name": definition.get("name", identifier), "value": value,
              "check_type": definition.get("check_type"), "category": definition.get("category", "other"),
              "adult": is_adult(definition), "status": "unknown", "attempted": False,
              "url": substitute(definition.get("url") or "https://" + definition.get("domain", ""),
                                {"username": value, "email": value}, True)}
    if definition.get("disabled"):
        return {**result, "status": "skipped", "detail": definition.get("disabled_reason", "Disabled upstream")}
    if (definition.get("recovery") or definition.get("flow") == "password-recovery") and not include_recovery:
        return {**result, "status": "skipped", "detail": "Recovery flow requires --include-recovery"}
    try:
        if definition.get("regexCheck") and not re.fullmatch(definition["regexCheck"], value):
            return {**result, "status": "skipped", "detail": "Identifier fails site username format"}
        with requests.Session() as session:
            result["attempted"] = True
            if definition.get("handler"):
                from profil3r.site_handlers import run_handler
                status, detail, code = run_handler(session, definition, value, timeout)
            else:
                response, (status, detail) = declarative_request(session, definition, value, timeout)
                code = response.status_code
        return {**result, "status": status, "detail": detail, "http_status": code}
    except requests.RequestException as exc:
        return {**result, "status": "error", "detail": type(exc).__name__}
    except (ValueError, KeyError, TypeError, AttributeError, IndexError, re.error) as exc:
        return {**result, "status": "unknown", "detail": str(exc)}


def scan_definitions(values, definitions, workers=4, timeout=8, include_recovery=False, progress=None):
    if not 1 <= workers <= 16:
        raise ValueError("workers must be between 1 and 16")
    if not 0 < timeout <= 120:
        raise ValueError("timeout must be greater than 0 and at most 120 seconds")
    values = list(dict.fromkeys(value.strip() for value in values if value.strip()))
    if any("@" in value for value in values) and any(d.get("check_type") == "username-url" for d in definitions.values()):
        raise ValueError("Username checks require handles, not email addresses")
    if len(values) > 50:
        raise ValueError("At most 50 identifiers per scan")
    total = len(values) * len(definitions)
    findings = []
    if progress:
        progress(0, total, None)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending = {executor.submit(probe_site, value, key, definition, timeout, include_recovery)
                   for value in values for key, definition in definitions.items()}
        while pending:
            done, pending = wait(pending, timeout=5, return_when=FIRST_COMPLETED)
            if not done and progress:
                progress(len(findings), total, None)
            for future in done:
                finding = future.result()
                findings.append(finding)
                if progress:
                    progress(len(findings), total, finding)
    return sorted(findings, key=lambda item: (item["value"], item["site"]))
