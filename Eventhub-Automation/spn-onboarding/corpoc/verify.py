"""Required-permissions check with the SPN's own credentials (what the Hub would run).

For each API: a client-credentials token, whose `roles` claim lists the
permissions actually granted. For each capability: granted vs expected, then
one read call (the same calls as the v3.2 script's verification).
"""

from .auth import HttpError, claims, client_credentials, error_text, http
from .catalog import AUDIENCE, BY_KEY, MESSAGE_TRACE_APP_ID

TEST_BASE = {
    "Graph": "https://graph.microsoft.com",
    "Management": "https://manage.office.com",
    "DefenderATP": "https://api.securitycenter.microsoft.com",
}


def _token_hint(exc):
    text = error_text(exc.body)
    if "AADSTS7000215" in text:
        return "secret not accepted yet (a new secret can take a minute to work)"
    if "AADSTS700016" in text:
        return "the app is not in this tenant yet: consent not done here, or still replicating"
    if "AADSTS500011" in text:
        return "this API is not in the tenant (product not licensed)"
    return text


def _test_hint(cap_key, status):
    if cap_key == "mailflow" and status in (401, 403):
        return (f" The Message Trace service principal ({MESSAGE_TRACE_APP_ID}) may be missing or "
                "still provisioning in this tenant (Microsoft: up to a few hours).")
    if status in (401, 403):
        return " Permissions can take a few minutes to apply after consent: re-check shortly."
    return ""


def verify(tenant, client_id, secret, cap_keys, unavailable=()):
    """unavailable: API keys the provisioning skipped because the tenant does not have them."""
    caps = [BY_KEY[k] for k in cap_keys]
    apis = sorted({a for c in caps for a in c.perms})
    tokens, api_state = {}, {}
    for api in apis:
        audience = AUDIENCE.get(api)
        if not audience:
            api_state[api] = {"roles": set(), "note": "not checked by the PoC"}
            continue
        try:
            tok = client_credentials(tenant, client_id, secret, audience)
        except HttpError as exc:
            api_state[api] = {"roles": set(), "note": _token_hint(exc)}
            continue
        roles = set(claims(tok).get("roles") or [])
        tokens[api] = tok
        if roles:
            note = ""
        elif api in unavailable:
            note = "this API is not in the tenant, so nothing could be granted (product not licensed)"
        else:
            note = "token has no permissions yet (consent can take a few minutes)"
        api_state[api] = {"roles": roles, "note": note}

    rows = []
    for cap in caps:
        expected = [(a, n) for a, names in cap.perms.items() for n in names]
        granted = [(a, n) for a, n in expected if n in api_state[a]["roles"]]
        missing = [f"{a}: {n}" for a, n in expected if (a, n) not in granted]
        unchecked = [a for a in cap.perms if AUDIENCE.get(a) is None]
        if unchecked and not granted:
            status, detail = "NOT CHECKED", "this API is not verified by the PoC"
        elif not granted:
            notes = sorted({api_state[a]["note"] for a in cap.perms if api_state[a]["note"]})
            status, detail = "MISSING", "; ".join(notes) or "none of its permissions are granted"
        elif cap.test and cap.test[0] in tokens:
            api, path = cap.test
            st, body = http("GET", TEST_BASE[api] + path.replace("{tenant}", tenant), token=tokens[api])
            if st < 300:
                status, detail = ("OK" if not missing else "PARTIAL"), f"read test HTTP {st}"
            else:
                status = "FAIL"
                detail = f"read test HTTP {st}: {error_text(body)}.{_test_hint(cap.key, st)}"
        else:
            status = "OK" if not missing else "PARTIAL"
            detail = ("permissions granted (write permissions are not exercised by the PoC)" if cap.response
                      else "permissions granted (no read test for this capability)")
        rows.append({"key": cap.key, "title": cap.title, "status": status, "granted": len(granted),
                     "total": len(expected), "missing": missing, "detail": detail})
    api_notes = {a: {"granted": len(s["roles"]), "note": s["note"]} for a, s in api_state.items()}
    return rows, api_notes
