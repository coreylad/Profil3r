"""Native handlers for the five bespoke flows referenced by the bundled corpus.

Endpoint contracts follow MailAccess (MIT; see MAILACCESS-LICENSE). Unexpected
responses stay unknown, and catch-all controls never count as account evidence.
"""
import secrets
from urllib.parse import quote

from profil3r.site_probe import classify, declarative_request


def _control(email):
    return "profil3r" + secrets.token_hex(8) + "@" + email.rsplit("@", 1)[1]


def _json(response):
    if response.status_code != 200:
        return {}
    try:
        body = response.json()
        return body if isinstance(body, dict) else {}
    except ValueError:
        return {}


def run_handler(session, definition, email, timeout):
    handler = definition["handler"]
    if handler == "control_email":
        response, real = declarative_request(session, definition, email, timeout)
        if real[0] != "possible_match":
            return *real, response.status_code
        control_response, control = declarative_request(session, definition, _control(email), timeout)
        if control[0] == "not_found":
            return "possible_match", "Target signal differs from random same-domain control", response.status_code
        return "unknown", "Control failed to disambiguate catch-all response", control_response.status_code
    if handler == "office365":
        base = "https://outlook.office365.com/autodiscover/autodiscover.json/v1.0/"
        kwargs = {"timeout": timeout, "allow_redirects": False,
                  "headers": {"User-Agent": "Profil3r/1.2"}}
        control = session.get(base + quote(_control(email), safe="") + "?Protocol=Autodiscoverv1", **kwargs)
        # Only an explicit missing-user reply is a valid control; not a WAF/error.
        if control.status_code != 404:
            return "unknown", "Autodiscover control was not an explicit missing-user response", control.status_code
        response = session.get(base + quote(email, safe="") + "?Protocol=Autodiscoverv1", **kwargs)
        if response.status_code == 200 and _json(response).get("Url"):
            return "possible_match", "Autodiscover response differs from control", 200
        if response.status_code == 404:
            return "not_found", "Autodiscover missing-user response", 404
        return "unknown", "Unexpected autodiscover response", response.status_code
    if handler == "adobe_recovery":
        response = session.post("https://auth.services.adobe.com/signin/v1/authenticationstate",
                                json={"username": email, "accountType": "individual"}, timeout=timeout,
                                headers={"X-IMS-CLIENTID": "adobedotcom2", "Content-Type": "application/json",
                                         "Origin": "https://auth.services.adobe.com"})
        body = _json(response)
        if body.get("errorCode") in ("user_not_found", "USER_NOT_FOUND"):
            return "not_found", "Provider explicitly reports missing user", response.status_code
        if body and response.headers.get("X-IMS-Authentication-State-Encrypted"):
            return "possible_match", "Provider returned authentication state", response.status_code
        return "unknown", "No explicit Adobe existence signal", response.status_code
    if handler == "odnoklassniki_recovery":
        response = session.get("https://ok.ru/dk", timeout=timeout,
                               params={"cmd": "AnonymRecoveryEnterLogin", "st.cmd": "anonymRecoveryEnterLogin",
                                       "st.email": email}, allow_redirects=True)
        return *classify({"checkType": "message", "presenseStrs": ["offer_contact_rest"],
                          "absenceStrs": ["home_rest"]}, response), response.status_code
    if handler == "okcupid":
        base = "https://e2p-okapi.api.okcupid.com/graphql/"
        device = secrets.token_hex(11)
        headers = {"User-Agent": "Android 115.1.0", "Accept": "application/json",
                   "Content-Type": "application/json", "x-okcupid-device-id": "Android; Pixel 6; 13; " + device + ";",
                   "x-okcupid-platform": "Android", "x-okcupid-version": "115.1.0", "x-okcupid-locale": "en-US"}
        response = session.post(base + "AnonAuthToken", timeout=timeout,
                                headers={**headers, "x-apollo-operation": "AnonAuthToken"},
                                json={"operationName": "AnonAuthToken", "variables": {"input": {"deviceId": device, "siteCode": 36}},
                                      "query": "mutation AnonAuthToken($input: AuthAnonymousInput!) { authAnonymous(input: $input) { token } }"})
        token = (_json(response).get("data") or {}).get("authAnonymous") or {}
        if not token.get("token"):
            return "unknown", "Anonymous token unavailable", response.status_code

        def valid(address):
            reply = session.post(base + "ValidateEmail", timeout=timeout,
                                 headers={**headers, "x-apollo-operation": "ValidateEmail", "authorization": token["token"]},
                                 json={"operationName": "ValidateEmail", "variables": {"email": address},
                                       "query": "query ValidateEmail($email: String!) { auth { isEmailValid(email: $email) } }"})
            value = ((_json(reply).get("data") or {}).get("auth") or {}).get("isEmailValid")
            return value if isinstance(value, bool) else None

        real = valid(email)
        if real is True:
            return "not_found", "Email is available", 200
        if real is False and valid(_control(email)) is True:
            return "possible_match", "Unavailable target with available same-domain control", 200
        return "unknown", "Validation/control did not distinguish target", None
    return "unknown", "Unsupported handler: " + handler, None
