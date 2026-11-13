"""Graph operations shared by both methods."""

import time
import urllib.parse

from .auth import HttpError, graph


def _odata_str(value):
    return "'" + value.replace("'", "''") + "'"


def find_sp(token, app_id):
    flt = urllib.parse.quote(f"appId eq {_odata_str(app_id)}")
    found = graph("GET", f"/servicePrincipals?$filter={flt}&$select=id,appId,displayName,appRoles", token)
    return (found.get("value") or [None])[0]


def find_app(token, display_name=None, app_id=None):
    """An app registration by its client ID (preferred) or its display name."""
    flt = f"appId eq {_odata_str(app_id)}" if app_id else f"displayName eq {_odata_str(display_name)}"
    found = graph("GET", f"/applications?$filter={urllib.parse.quote(flt)}"
                         "&$select=id,appId,displayName,web,publicClient,passwordCredentials", token)
    return (found.get("value") or [None])[0]


def ensure_sp(token, app_id, attempts=6, wait=5):
    """The service principal of app_id, created if missing. A new app registration
    takes a few seconds to replicate, so creation is retried."""
    sp = find_sp(token, app_id)
    if sp:
        return sp, False
    for attempt in range(attempts):
        try:
            return graph("POST", "/servicePrincipals", token, {"appId": app_id}), True
        except HttpError as exc:
            if attempt == attempts - 1 or exc.status not in (400, 404):
                raise
            time.sleep(wait)


def resolve_permissions(token, perms, create_missing_sp=False):
    """Permission names -> app role IDs in this tenant.

    Returns (resolved, skipped). resolved: dicts with api, name, resourceAppId,
    resourceSpId, roleId. skipped: (api, name, reason) for APIs the tenant does
    not have (product not licensed) or roles the API does not offer.
    """
    from .catalog import API

    resolved, skipped = [], []
    for api_key, names in perms.items():
        app_id = API[api_key]
        sp = find_sp(token, app_id)
        if sp is None and create_missing_sp:
            try:
                sp, _ = ensure_sp(token, app_id, attempts=1)
            except HttpError:
                sp = None
        if sp is None:
            skipped += [(api_key, n, "API not available in this tenant") for n in names]
            continue
        roles = {r["value"]: r for r in sp.get("appRoles") or []
                 if "Application" in (r.get("allowedMemberTypes") or [])}
        for name in names:
            role = roles.get(name)
            if role is None:
                skipped.append((api_key, name, "permission not offered by this API"))
                continue
            resolved.append({"api": api_key, "name": name, "resourceAppId": app_id,
                             "resourceSpId": sp["id"], "roleId": role["id"]})
    return resolved, skipped


def required_resource_access(resolved):
    by_api = {}
    for p in resolved:
        by_api.setdefault(p["resourceAppId"], []).append({"id": p["roleId"], "type": "Role"})
    return [{"resourceAppId": k, "resourceAccess": v} for k, v in by_api.items()]


def add_secret(token, app_object_id, months, label):
    end = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + months * 30 * 86400))
    pw = graph("POST", f"/applications/{app_object_id}/addPassword", token,
               {"passwordCredential": {"displayName": label, "endDateTime": end}})
    return pw["secretText"], pw["endDateTime"], pw.get("keyId")


LOGO = __import__("pathlib").Path(__file__).resolve().parent / "static" / "cor-logo.png"


def set_logo(token, app_object_id):
    """Upload cor.'s logo to an app registration: Microsoft shows it on the sign-in and
    consent screens and in Entra. False when there is no logo file."""
    from .auth import GRAPH, http
    if not LOGO.exists():
        return False
    status, body = http("PUT", f"{GRAPH}/v1.0/applications/{app_object_id}/logo", token=token,
                        raw=LOGO.read_bytes(), content_type="image/png")
    if status >= 400:
        raise HttpError(status, body)
    return True


def remove_secret(token, app_object_id, key_id):
    graph("POST", f"/applications/{app_object_id}/removePassword", token, {"keyId": key_id})
