"""Method 2 portal: "Create the cor. SPN in my tenant" (http://localhost:8401).

The customer's admin picks the capabilities and signs in once. With the admin's
delegated token (held in memory for this one request, never stored) the page
does in the customer's tenant what provision-azure-spn-v3.2.ps1 does:

  1. creates a single-tenant app registration + service principal OWNED BY THE CUSTOMER
  2. grants its application permissions (the equivalent of admin consent)
  3. creates the Message Trace service principal (mail flow) and assigns the
     Exchange Administrator role (basic email response) when chosen
  4. creates the client secret
  5. optionally removes cor.'s onboarding app from the tenant

then runs the required-permissions check with the new SPN's own credentials.
"""

import secrets
import time
import urllib.parse

from corpoc import auth, catalog, graphops, store
from corpoc.verify import verify
from corpoc.web import Redirect, as_list, esc, mask, page, serve, verification_html

PRODUCT = "Method 2 — sign in and we create it"
PENDING = {}  # state -> sign-in request (one-time, in memory)
SESSIONS = {}  # manage session id -> admin token + connection (memory only, MANAGE_MINUTES)
MANAGE_MINUTES = 10
DEFAULT_CAPS = ("m365audit", "entra", "defender", "mailflow")
GRAPH_SCOPE = "https://graph.microsoft.com/"
SECRET_LABEL = "cor. Hub (PoC)"


def onboarding_app():
    return store.load("method2", "onboarding-app")



def _needs_role(keys):
    return any("exchange-admin-role" in catalog.BY_KEY[k].needs for k in keys if k in catalog.BY_KEY)


def scopes_for(keys, previous_keys=()):
    """Least privilege per session: the role scope only when the role is assigned,
    or has to be removed because an earlier run of this connection assigned it."""
    scopes = ["openid", "profile", GRAPH_SCOPE + "Application.ReadWrite.All",
              GRAPH_SCOPE + "AppRoleAssignment.ReadWrite.All"]
    if _needs_role(keys) or _needs_role(previous_keys):
        scopes.append(GRAPH_SCOPE + "RoleManagement.ReadWrite.Directory")
    return scopes


# --- Wizard pages ---------------------------------------------------------------

API_NAMES = {"Graph": "Microsoft Graph", "Exchange": "Office 365 Exchange Online",
             "Management": "Office 365 Management APIs", "SharePoint": "SharePoint Online",
             "DefenderATP": "Microsoft Defender for Endpoint", "ThreatProtect": "Microsoft Threat Protection"}
SCOPE_TEXT = {"Application.ReadWrite.All": "Create and update the cor. app registration in your tenant",
              "AppRoleAssignment.ReadWrite.All": "Grant that app the permissions listed on this page",
              "RoleManagement.ReadWrite.Directory": "Assign (or remove) the Exchange Administrator role for email response"}
MS_LOGO = ("<svg viewBox='0 0 21 21'><rect width='10' height='10' fill='#f25022'/><rect x='11' width='10' height='10' "
           "fill='#7fba00'/><rect y='11' width='10' height='10' fill='#00a4ef'/><rect x='11' y='11' width='10' "
           "height='10' fill='#ffb900'/></svg>")


def _svg(body, box="0 0 24 24"):
    return (f"<svg class='ico' viewBox='{box}' fill='none' stroke='currentColor' stroke-width='1.5' "
            f"stroke-linecap='round' stroke-linejoin='round'>{body}</svg>")


ICONS = {
    "m365audit": _svg("<rect x='5' y='3' width='14' height='18' rx='2'/><path d='M9 8h6M9 12h6M9 16h4'/>"),
    "entra": _svg("<circle cx='12' cy='8' r='4'/><path d='M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6'/>"),
    "defender": _svg("<path d='M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z'/><path d='M9 12l2 2 4-4'/>"),
    "mde": _svg("<rect x='3' y='5' width='18' height='12' rx='1.5'/><path d='M2 20h20'/>"),
    "mailflow": _svg("<rect x='3' y='5' width='18' height='14' rx='2'/><path d='M3 7l9 6 9-6'/>"),
    "purview": _svg("<circle cx='11' cy='11' r='6'/><path d='M20 20l-4.5-4.5'/>"),
    "intune": _svg("<rect x='7' y='2.5' width='10' height='19' rx='2'/><path d='M11 18h2'/>"),
    "threatintel": _svg("<circle cx='12' cy='12' r='8'/><circle cx='12' cy='12' r='4'/><circle cx='12' cy='12' r='.8'/>"),
    "directory": _svg("<circle cx='12' cy='5' r='2.5'/><circle cx='5' cy='18' r='2.5'/><circle cx='19' cy='18' r='2.5'/>"
                      "<path d='M11 7.2L6.3 16M13 7.2l4.7 8.8M7.5 18h9'/>"),
    "sharepoint": _svg("<path d='M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z'/>"),
    "endpoint": _svg("<path d='M13 2L4 14h7l-1 8 9-12h-7z'/>"),
    "identity": _svg("<circle cx='8' cy='12' r='4'/><path d='M12 12h9M18 12v3M21 12v2'/>"),
    "emailbasic": _svg("<rect x='3' y='5' width='18' height='14' rx='2'/><path d='M3 7l9 6 9-6M15 15l4 4M19 15l-4 4'/>"),
}

ILL_TERMS = ("<svg class='ill' viewBox='0 0 92 70'><rect x='30' y='4' width='50' height='60' rx='3' fill='var(--card)' "
             "stroke='var(--line)'/><path d='M38 22h34M38 30h34M38 38h26' stroke='var(--line)' stroke-width='3'/>"
             "<circle cx='30' cy='52' r='11' fill='var(--accent)' opacity='.18'/><path d='M24 52l5 5 9-11' fill='none' "
             "stroke='var(--accent)' stroke-width='4' stroke-linecap='round'/></svg>")
ILL_PERMS = ("<svg class='ill' viewBox='0 0 92 70'><rect x='16' y='20' width='70' height='38' rx='3' fill='var(--accent)'/>"
             "<rect x='8' y='12' width='70' height='38' rx='3' fill='var(--soft)' stroke='var(--line)'/>"
             "<circle cx='22' cy='26' r='6' fill='var(--accent2)' opacity='.35'/></svg>")
ILL_MS = ("<svg class='ill' viewBox='0 0 92 70'><rect x='12' y='4' width='68' height='62' rx='3' fill='var(--card)' "
          "stroke='var(--line)'/><g transform='translate(41 10) scale(.5)'>" + MS_LOGO[MS_LOGO.index('<rect'):-6] +
          "</g><path d='M22 30h48M22 38h48' stroke='var(--line)' stroke-width='3'/><rect x='22' y='48' width='48' "
          "height='9' rx='1.5' fill='var(--accent)'/></svg>")


def _carry(q):
    """The wizard's choices as (hidden inputs, query string), passed from step to step."""
    pairs = [("cap", k) for k in as_list(q.get("cap"))]
    pairs += [(k, q[k]) for k in ("name", "months", "renew", "cleanup", "tenant") if q.get(k)]
    hidden = "".join(f"<input type='hidden' name='{esc(k)}' value='{esc(v)}'>" for k, v in pairs)
    return hidden, urllib.parse.urlencode(pairs)


def _previous(name):
    return next((r for r in store.all_records("method2-conn") if r["appName"] == f"cor. SPN (PoC) - {name}"), None)


def index(_q):
    if not onboarding_app():
        return page("Set up first", "<p>Run <code>python method2_setup.py register</code> once, then reload.</p>",
                    PRODUCT, plain=True)
    rows = "".join(
        f"<tr><td><b>{esc(r['appName'])}</b><br><span class='muted'>{len(r['capabilities'])} capabilities</span></td>"
        f"<td><code>{esc(r['tenant'])}</code></td><td>{esc(r.get('updatedAt') or r['createdAt'])}</td>"
        f"<td><a href='/m2/verify?id={esc(r['id'])}'>Check permissions</a> · "
        f"<a href='/m2/setup?{urllib.parse.urlencode([('name', r['appName'].split(' - ', 1)[-1])] + [('cap', k) for k in r['capabilities']])}'>Change</a> · "
        f"<a href='/m2/manage?id={esc(r['id'])}'>Secrets / delete</a></td></tr>"
        for r in store.all_records("method2-conn"))
    body = (
        "<div class='split'><div><p class='eyebrow'>Welcome to cor.</p><h1>Integration Overview</h1>"
        "<p class='lead'>This wizard connects your <b>Microsoft 365 tenant</b> to cor. The process takes less than "
        "5 minutes, and nothing to install or run.</p>"
        "<p class='lead'>You'll need a <b>Global Administrator</b> (or Privileged Role Administrator) account to "
        "complete it.</p><p class='lead'>cor. creates an app <b>in your tenant, owned by you</b>: you can see, limit or "
        "delete it at any time, and cor. keeps no access of its own.</p></div><div>"
        f"<div class='stepcard'><div class='txt'><p class='eyebrow'>Step 1</p><h3>Choose what cor. monitors</h3>"
        f"<p>Pick the logs cor. collects and, optionally, the response actions it may run.</p></div>{ILL_TERMS}</div>"
        f"<div class='stepcard'><div class='txt'><p class='eyebrow'>Step 2</p><h3>Review Permissions"
        f"<span class='badge ro'>Read-Only by default</span></h3><p>See every permission cor. will be granted before "
        f"anything is created.</p></div>{ILL_PERMS}</div>"
        f"<div class='stepcard'><div class='txt'><p class='eyebrow'>Step 3</p><h3>Authorize with Microsoft</h3>"
        f"<p>You'll be taken to the Microsoft login page and sign in with your admin account.</p></div>{ILL_MS}</div>"
        "<div class='actions'><span></span><a class='btn right' href='/m2/setup'>Get Started</a></div></div></div>"
        + (f"<h2 id='connections' style='margin-top:40px'>Your connections</h2><table><tr><th>Connection</th>"
           f"<th>Tenant</th><th>Last change</th><th></th></tr>{rows}</table>" if rows else ""))
    return page("Integration Overview", body, PRODUCT, step=8)


def setup_page(q):
    first = "name" not in q
    chosen = set(DEFAULT_CAPS if first else as_list(q.get("cap")))

    def pick(c):
        on = " checked" if c.key in chosen else ""
        badge = "<span class='badge rw'>Makes changes</span>" if c.response else ""
        return (f"<label class='pick'><input type='checkbox' name='cap' value='{c.key}'{on}>"
                f"<b>{esc(c.title)}{badge}</b><span>{esc(c.description)}</span></label>")

    err = f"<div class='note warn'>{esc(q['error'])}</div>" if q.get("error") else ""
    cleanup = " checked" if first or q.get("cleanup") == "1" else ""
    renew = " checked" if q.get("renew") == "1" else ""
    body = (
        "<div class='split'><div><p class='eyebrow'>Step 1 of 3</p><h1>Choose what cor. monitors</h1>"
        "<p class='lead'>Logs are read-only. Response actions let cor. act in your tenant (isolate a device, "
        "disable a user, purge a message) and are off unless you pick them.</p>"
        "<p class='lead'>You can change this later: run the wizard again with the same connection name.</p></div>"
        f"<form method='get' action='/m2/review'>{err}"
        f"<label class='field'><span>Connection name</span><input type='text' name='name' value='{esc(q.get('name') or 'Production')}' required>"
        "<span class='muted' style='font-weight:400;font-size:13px'>The app is created as "
        "<code>cor. SPN (PoC) - &lt;name&gt;</code>. An existing name updates that connection.</span></label>"
        f"<h2>Logs <span class='badge ro'>Read-Only</span></h2><div class='grid'>"
        + "".join(pick(c) for c in catalog.CAPABILITIES if not c.response) +
        "</div><h2>Response actions <span class='badge rw'>Optional</span></h2><div class='grid'>"
        + "".join(pick(c) for c in catalog.CAPABILITIES if c.response) +
        "</div><details style='margin-top:20px'><summary>Advanced options</summary><div style='margin-top:12px'>"
        f"<label class='field'><span>Secret validity (months, for a new secret)</span><input type='number' name='months' "
        f"value='{esc(q.get('months') or '6')}' min='1' max='24'></label>"
        f"<label><input type='checkbox' name='renew' value='1'{renew}> Renew the secret (replaces the current one)</label>"
        f"<label><input type='checkbox' name='cleanup' value='1'{cleanup}> Remove cor.'s onboarding app from my tenant when done</label>"
        f"<label class='field' style='margin-top:12px'><span>Your tenant domain (optional, skips the account picker)</span>"
        f"<input type='text' name='tenant' value='{esc(q.get('tenant') or '')}' placeholder='contoso.onmicrosoft.com'></label>"
        "</div></details><div class='actions'><a class='btn secondary' href='/'>Go Back</a>"
        "<button class='btn right'>Next: Review Permissions</button></div></form></div>")
    return page("Choose what cor. monitors", body, PRODUCT, step=33)


def review_page(q):
    try:
        keys = catalog.parse_caps(as_list(q.get("cap")))
    except ValueError as exc:
        _, qs = _carry(q)
        return Redirect(f"/m2/setup?{qs}&error={urllib.parse.quote(str(exc).capitalize())}")
    name = (q.get("name") or "Production").strip()[:60]
    months = max(1, min(24, int(q.get("months") or 6)))
    hidden, qs = _carry(q)
    prev = _previous(name)

    def card(c):
        apis = "".join(f"<li><b>{esc(API_NAMES.get(api, api))}</b>: "
                       + ", ".join(f"<code>{esc(n)}</code>" for n in names) + "</li>"
                       for api, names in c.perms.items())
        extra = ""
        if "message-trace-sp" in c.needs:
            extra = "<li>Adds Microsoft's Message Trace service to your tenant (needed by the message trace API)</li>"
        if "exchange-admin-role" in c.needs:
            extra = "<li>Assigns the <b>Exchange Administrator</b> role to the cor. app</li>"
        badge = "<span class='badge rw'>Read-Write</span>" if c.response else "<span class='badge ro'>Read-Only</span>"
        return (f"<div class='permcard'>{ICONS.get(c.key, '')}<div class='txt'><h3>{esc(c.title)}{badge}</h3>"
                f"<p>{esc(c.description)}</p><details><summary>See details</summary><ul>{apis}{extra}</ul></details>"
                "</div></div>")

    if q.get("renew") == "1":
        secret = f"A <b>new secret</b> valid {months} month(s); the previous one is removed"
    elif prev:
        secret = "The <b>existing secret is kept</b>: the connectors need no change"
    else:
        secret = f"A client secret valid <b>{months} month(s)</b>, handed to the cor. connectors"
    update = ""
    if prev:
        dropped = [catalog.BY_KEY[k].title for k in prev["capabilities"] if k not in keys and k in catalog.BY_KEY]
        update = ("<div class='note'>This <b>updates</b> the existing connection <b>" + esc(prev["appName"]) +
                  "</b>: same app and client ID, and its permissions are changed to match this page."
                  + (" Removed: " + esc(", ".join(dropped)) + "." if dropped else "") + "</div>")
    scopes = [sc.split("/")[-1] for sc in scopes_for(keys, prev["capabilities"] if prev else ())
              if sc.startswith(GRAPH_SCOPE)]
    body = (
        "<div class='split'><div><p class='eyebrow'>Step 2 of 3</p><h1>API Permission Preview</h1>"
        "<p class='lead'>Please review the permissions cor. will be granted in your tenant.</p>"
        "<h2>When you authorize, cor. will</h2><ul class='steps'>"
        f"<li class='ok'>Create the app <b>cor. SPN (PoC) - {esc(name)}</b> in your tenant, owned by you</li>"
        "<li class='ok'>Grant it only the permissions listed here</li>"
        f"<li class='ok'>{secret}</li>"
        f"<li class='ok'>{'Remove' if q.get('cleanup') == '1' else 'Keep'} its onboarding app in your tenant afterwards</li></ul>"
        "<h2>Microsoft will ask you to allow</h2><ul class='steps'>"
        + "".join(f"<li>{esc(SCOPE_TEXT.get(sc, sc))}</li>" for sc in scopes) +
        "</ul><p class='muted' style='font-size:13.5px'>On your behalf, <b>during this sign-in only</b>. "
        "cor. keeps no access of its own.</p></div>"
        f"<div>{update}" + "".join(card(catalog.BY_KEY[k]) for k in keys) +
        f"<form method='post' action='/m2/start'>{hidden}<div class='actions'>"
        f"<a class='btn secondary' href='/m2/setup?{esc(qs)}'>Go Back</a>"
        f"<button class='btn ms right'>{MS_LOGO} Next: Authorize with Microsoft</button></div></form></div></div>")
    return page("API Permission Preview", body, PRODUCT, step=66)


def _result(title, eyebrow, lead, right, record=None, ok=True):
    left = f"<p class='eyebrow'>{esc(eyebrow)}</p><h1>{esc(title)}</h1><p class='lead'>{lead}</p>"
    if record:
        left += ("<dl class='kv'>"
                 f"<dt>Tenant ID</dt><dd><code>{esc(record['tenant'])}</code></dd>"
                 f"<dt>Client ID</dt><dd><code>{esc(record['appId'])}</code></dd>"
                 f"<dt>Client secret</dt><dd>{esc(mask(record.get('secret')))}</dd>"
                 f"<dt>Secret expires</dt><dd>{esc((record.get('secretExpires') or '—')[:10])}</dd></dl>"
                 "<p class='muted' style='font-size:13.5px'>The cor. connectors receive these as today: "
                 "no connector change.</p>")
    actions = (f"<a class='btn' href='/m2/verify?id={esc(record['id'])}'>Check the permissions now</a>"
               if record else "<a class='btn' href='/m2/setup'>Try again</a>")
    body = (f"<div class='split'><div>{left}</div><div>{right}<div class='actions'>"
            f"<a class='btn secondary' href='/'>Back to connections</a><span class='right'>{actions}</span>"
            "</div></div></div>")
    return page(title, body, PRODUCT, step=100 if ok else 66)


def start(form):
    app = onboarding_app()
    try:
        keys = catalog.parse_caps(as_list(form.get("cap")))
    except ValueError as exc:
        return Redirect(f"/m2/setup?{_carry(form)[1]}&error={urllib.parse.quote(str(exc).capitalize())}")
    verifier, challenge = auth.pkce()
    state = secrets.token_urlsafe(16)
    name = (form.get("name") or "Production").strip()[:60]
    previous = [r for r in store.all_records("method2-conn") if r["appName"] == f"cor. SPN (PoC) - {name}"]
    scopes = scopes_for(keys, [k for r in previous for k in r["capabilities"]])
    PENDING[state] = {"keys": keys, "name": name, "renew": form.get("renew") == "1",
                      "months": max(1, min(24, int(form.get("months") or 6))),
                      "cleanup": form.get("cleanup") == "1", "verifier": verifier, "scopes": scopes}
    tenant = (form.get("tenant") or "").strip() or "organizations"
    PENDING[state]["tenant"] = tenant
    return Redirect(auth.authorize_url(tenant, app["appId"], app["redirectUri"], scopes, state, challenge))


def provision(token, req, onboarding_app_id):
    """Create the SPN in the signed-in admin's tenant. Returns (record, steps)."""
    steps = []

    def step(kind, text):
        steps.append((kind, text))

    c = auth.claims(token)
    tenant, who = c["tid"], c.get("upn") or c.get("preferred_username")
    step("ok", f"Signed in as {who} (tenant {tenant}). Acting with the admin's delegated rights; "
               "the token is used for this request only and is not stored.")

    resolved, skipped = graphops.resolve_permissions(token, catalog.perms_for(req["keys"]))
    for api, perm, why in skipped:
        step("warn", f"Skipped {api}: {perm} — {why}")

    name = f"cor. SPN (PoC) - {req['name']}"
    rec_id = f"{tenant}-{store.slug(req['name'])}"
    previous = store.load("method2-conn", rec_id)
    rra = graphops.required_resource_access(resolved)
    app = ((graphops.find_app(token, app_id=previous["appId"]) if previous else None)
           or graphops.find_app(token, name))
    if app:
        auth.graph("PATCH", f"/applications/{app['id']}", token,
                   {"displayName": name, "requiredResourceAccess": rra})
        step("ok", f"Updated the existing app registration '{name}' (client ID {app['appId']}): same SPN.")
    else:
        app = auth.graph("POST", "/applications", token, {
            "displayName": name, "signInAudience": "AzureADMyOrg", "requiredResourceAccess": rra,
            "notes": "Created by the cor. onboarding PoC. Used by cor. connectors to read security logs."})
        step("ok", f"Created app registration '{name}' (client ID {app['appId']}), single-tenant, owned by your tenant.")

    try:
        graphops.set_logo(token, app["id"])
    except auth.HttpError as exc:
        step("warn", f"Could not set the cor. logo on the app (it works without it) — {exc}")

    sp, created = graphops.ensure_sp(token, app["appId"])
    step("ok", f"{'Created' if created else 'Found'} its service principal (object ID {sp['id']}).")

    # Permissions: make the grants match the chosen capabilities exactly.
    current = auth.graph("GET", f"/servicePrincipals/{sp['id']}/appRoleAssignments"
                                "?$select=id,resourceId,resourceDisplayName,appRoleId", token).get("value", [])
    have = {(a["resourceId"], a["appRoleId"]): a for a in current}
    wanted = {(p["resourceSpId"], p["roleId"]) for p in resolved}
    granted = already = removed = 0
    for p in resolved:
        if (p["resourceSpId"], p["roleId"]) in have:
            already += 1
            continue
        for attempt in range(4):
            try:
                auth.graph("POST", f"/servicePrincipals/{p['resourceSpId']}/appRoleAssignedTo", token,
                           {"principalId": sp["id"], "resourceId": p["resourceSpId"], "appRoleId": p["roleId"]})
                granted += 1
                break
            except auth.HttpError as exc:
                if attempt == 3 or exc.status not in (400, 404):  # a new SP can take seconds to replicate
                    step("fail", f"Could not grant {p['api']}: {p['name']} — {exc}")
                    break
                time.sleep(4)
    for key, assignment in have.items():
        if key in wanted:
            continue
        try:
            auth.graph("DELETE", f"/servicePrincipals/{sp['id']}/appRoleAssignments/{assignment['id']}", token)
            removed += 1
        except auth.HttpError as exc:
            step("fail", f"Could not remove a {assignment.get('resourceDisplayName')} permission — {exc}")
    step("ok", f"Permissions now match the chosen capabilities (admin consent): {granted} granted, "
               f"{removed} removed, {already} unchanged.")

    if any("message-trace-sp" in catalog.BY_KEY[k].needs for k in req["keys"]):
        try:
            _, mt_created = graphops.ensure_sp(token, catalog.MESSAGE_TRACE_APP_ID, attempts=1)
            step("ok", "Created the Message Trace service principal (Microsoft: can take a few hours to become active)."
                 if mt_created else "The Message Trace service principal already exists.")
        except auth.HttpError as exc:
            step("fail", f"Could not create the Message Trace service principal — {exc}")

    want_role = _needs_role(req["keys"])
    if want_role or (previous and _needs_role(previous["capabilities"])):
        flt = urllib.parse.quote(f"principalId eq '{sp['id']}' and roleDefinitionId eq '{catalog.EXCHANGE_ADMIN_ROLE_ID}'")
        try:
            existing = auth.graph("GET", f"/roleManagement/directory/roleAssignments?$filter={flt}", token).get("value")
            if want_role and existing:
                step("ok", "The SPN already has the Exchange Administrator role.")
            elif want_role:
                auth.graph("POST", "/roleManagement/directory/roleAssignments", token,
                           {"principalId": sp["id"], "roleDefinitionId": catalog.EXCHANGE_ADMIN_ROLE_ID,
                            "directoryScopeId": "/"})
                step("ok", "Assigned the Exchange Administrator role to the SPN (basic email response).")
            elif existing:
                for ra in existing:
                    auth.graph("DELETE", f"/roleManagement/directory/roleAssignments/{ra['id']}", token)
                step("ok", "Removed the Exchange Administrator role (basic email response is no longer chosen).")
        except auth.HttpError as exc:
            step("fail", f"Could not update the Exchange Administrator role — {exc}")

    # Secret: keep the current one unless a renewal is asked for, or there is none to keep.
    ours = [c for c in app.get("passwordCredentials") or [] if c.get("displayName") == SECRET_LABEL]
    still_on_app = not previous or not previous.get("secretKeyId") or any(
        c.get("keyId") == previous["secretKeyId"] for c in ours)
    if previous and previous.get("secret") and not req["renew"] and still_on_app:
        secret, expires, key_id = previous["secret"], previous["secretExpires"], previous.get("secretKeyId")
        step("ok", f"Kept the existing client secret (valid until {expires[:10]}): the connectors need no change. "
                   "Tick 'Renew the secret' to replace it.")
        months = _validity_months(next((c for c in ours if _uses(previous, c)), None))
        if months is not None and months != req["months"]:
            step("warn", f"Secret validity not changed: the current secret was made for {months} month(s) and still "
                         f"expires on {expires[:10]}. Microsoft cannot change a secret's expiry, so the "
                         f"{req['months']} month(s) chosen apply to a new secret only: run again with 'Renew the "
                         "secret' to get one (the connectors then need the new secret).")
    else:
        secret, expires, key_id = graphops.add_secret(token, app["id"], req["months"], SECRET_LABEL)
        step("ok", f"Created a client secret, valid until {expires[:10]}.")
        old = [c for c in ours if c.get("keyId") != key_id]
        for c in old:
            try:
                graphops.remove_secret(token, app["id"], c["keyId"])
            except auth.HttpError as exc:
                step("warn", f"Could not remove an old secret — {exc}")
        if old:
            step("ok", f"Removed {len(old)} older secret(s): only the new one works now.")

    if req["cleanup"]:
        try:
            ob = graphops.find_sp(token, onboarding_app_id)
            if ob:
                auth.graph("DELETE", f"/servicePrincipals/{ob['id']}", token)
                step("ok", "Removed cor.'s onboarding app from your tenant: only the SPN you own remains.")
            else:
                step("ok", "cor.'s onboarding app is not registered in your tenant: only the SPN you own remains.")
        except auth.HttpError as exc:
            step("warn", f"Could not remove the onboarding app — {exc}. You can delete 'cor. onboarding (PoC)' "
                         "from Enterprise applications.")

    record = {"id": rec_id, "tenant": tenant, "signedInAs": who, "appName": name, "appId": app["appId"],
              "objectId": app["id"], "spId": sp["id"], "capabilities": req["keys"],
              "permissions": [f"{p['api']}: {p['name']}" for p in resolved],
              "skipped": [f"{a}: {n} ({w})" for a, n, w in skipped],
              "secret": secret, "secretExpires": expires, "secretKeyId": key_id,
              "createdAt": previous["createdAt"] if previous else time.strftime("%Y-%m-%d %H:%M:%S"),
              "updatedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
              "steps": steps}
    store.save("method2-conn", rec_id, record)
    return record, steps


def callback(q):
    req = PENDING.pop(q.get("state", ""), None)
    if q.get("error"):
        return _result("Sign-in was not completed", "Not created",
                       "Microsoft did not complete the sign-in, so nothing was created in your tenant.",
                       f"<div class='note warn'><span class='pill FAIL'>NOT CREATED</span> <code>{esc(q['error'])}</code> "
                       f"{esc(q.get('error_description', ''))}</div>", ok=False)
    if req is None:
        return 400, page("Unknown request", "<p>Start again from the <a href='/'>start page</a>.</p>", PRODUCT)
    if req.get("kind") == "manage":
        return manage_signed_in(q, req)
    app = onboarding_app()
    try:
        token = auth.redeem_code(req["tenant"], app["appId"], q["code"], app["redirectUri"],
                                 req["verifier"], req["scopes"])["access_token"]
    except auth.HttpError as exc:
        return _result("Sign-in was not completed", "Not created", "The sign-in could not be completed.",
                       f"<div class='note warn'>{esc(str(exc))}</div>", ok=False)
    try:
        record, steps = provision(token, req, app["appId"])
    except auth.HttpError as exc:
        return _result("The cor. app was not created", "Failed",
                       "The account needs Global Administrator or Privileged Role Administrator.",
                       f"<div class='note warn'><span class='pill FAIL'>FAILED</span> {esc(str(exc))}</div>", ok=False)
    finally:
        del token
    items = "".join(f"<li class='{k}'>{esc(t)}</li>" for k, t in steps)
    return _result(f"{record['appName']} is connected", "Done",
                   "The cor. app now lives in your tenant and belongs to you. New permissions can take a minute "
                   "to apply before the check shows them.",
                   f"<h2 style='margin-top:0'>What was done</h2><ul class='steps'>{items}</ul>", record)


def verify_page(q):
    record = store.load("method2-conn", q.get("id", ""))
    if not record:
        return 404, page("Unknown connection", "<p>Unknown connection.</p>", PRODUCT)
    if not record.get("secret"):
        return page(f"{record['appName']} — permissions check",
                    "<div class='card'><p>The Hub has no working secret for this SPN (it was removed). "
                    "Run the connection again from the <a href='/'>start page</a> with <b>Renew the secret</b>.</p></div>",
                    PRODUCT)
    unavailable = {s.split(":")[0] for s in record.get("skipped", []) if "API not available" in s}
    rows, api_notes = verify(record["tenant"], record["appId"], record["secret"], record["capabilities"], unavailable)
    values = {"Tenant ID": record["tenant"], "Client ID": record["appId"], "Client Secret": mask(record["secret"]),
              "Secret expires": record["secretExpires"][:10]}
    body = verification_html(rows, api_notes, values, f"/m2/verify?id={urllib.parse.quote(record['id'])}")
    return page(f"{record['appName']} — permissions check", body + "<p><a href='/'>← Back</a></p>", PRODUCT)


# --- Manage a connection: list / remove secrets, delete the SPN ----------------
# cor. has no access of its own, so every change is made with the admin's sign-in.
# The token stays in memory for this page only (MANAGE_MINUTES), and Finish drops
# it and removes the onboarding app from the tenant again.

def manage_page(q):
    record = store.load("method2-conn", q.get("id", ""))
    if not record:
        return 404, page("Unknown connection", "<p>Unknown connection. <a href='/'>Back</a></p>", PRODUCT)
    body = (f"<div class='card'><p>Manage <b>{esc(record['appName'])}</b> (client ID <code>{esc(record['appId'])}</code>) "
            f"in tenant <code>{esc(record['tenant'])}</code>: see every secret on the app, remove one, or delete the SPN.</p>"
            "<p class='muted'>cor. has no access to your tenant, so this needs your sign-in again (Global Administrator "
            f"or Application Administrator). Your token is kept in memory for this page only, up to {MANAGE_MINUTES} minutes.</p>"
            "<form method='post' action='/m2/manage/start'>"
            f"<input type='hidden' name='id' value='{esc(record['id'])}'>"
            "<p><button class='btn'>Sign in with Microsoft to manage</button> <a class='btn secondary' href='/'>Back</a></p>"
            "</form></div>")
    return page("Manage the cor. SPN", body, PRODUCT)


def manage_start(form):
    record = store.load("method2-conn", form.get("id", ""))
    if not record:
        return 404, page("Unknown connection", "<p>Unknown connection.</p>", PRODUCT)
    app = onboarding_app()
    verifier, challenge = auth.pkce()
    state = secrets.token_urlsafe(16)
    scopes = ["openid", "profile", GRAPH_SCOPE + "Application.ReadWrite.All"]
    PENDING[state] = {"kind": "manage", "id": record["id"], "tenant": record["tenant"],
                      "verifier": verifier, "scopes": scopes}
    return Redirect(auth.authorize_url(record["tenant"], app["appId"], app["redirectUri"], scopes, state, challenge))


def manage_signed_in(q, req):
    app = onboarding_app()
    try:
        token = auth.redeem_code(req["tenant"], app["appId"], q["code"], app["redirectUri"],
                                 req["verifier"], req["scopes"])["access_token"]
    except auth.HttpError as exc:
        return page("Sign-in was not completed", f"<div class='card'><p>{esc(str(exc))}</p>"
                                                 "<p><a class='btn secondary' href='/'>Back</a></p></div>", PRODUCT)
    sid = secrets.token_urlsafe(16)
    SESSIONS[sid] = {"token": token, "id": req["id"], "expires": time.time() + MANAGE_MINUTES * 60,
                     "onboardingAppId": app["appId"]}
    return Redirect(f"/m2/manage/session?sid={sid}")


def _session(sid):
    sess = SESSIONS.get(sid or "")
    if sess and time.time() > sess["expires"]:
        _close(sid)
        return None
    return sess


def _close(sid):
    """Drop the admin's token and remove the onboarding app from the tenant again."""
    sess = SESSIONS.pop(sid, None)
    if not sess:
        return ""
    try:
        ob = graphops.find_sp(sess["token"], sess["onboardingAppId"])
        if ob:
            auth.graph("DELETE", f"/servicePrincipals/{ob['id']}", sess["token"])
            return "Removed cor.'s onboarding app from your tenant."
        return ""
    except auth.HttpError as exc:
        return f"Could not remove the onboarding app ({exc}): delete 'cor. onboarding (PoC)' from Enterprise applications."


def _expired():
    return page("Session ended", "<div class='card'><p>This manage session has ended (finished or older than "
                f"{MANAGE_MINUTES} minutes). <a href='/'>Start again</a>.</p></div>", PRODUCT)


def _validity_months(cred):
    """How long a secret was made for, in whole months (as the form counts them), from Entra's dates."""
    if not cred or not cred.get("startDateTime") or not cred.get("endDateTime"):
        return None
    start = time.mktime(time.strptime(cred["startDateTime"][:19], "%Y-%m-%dT%H:%M:%S"))
    end = time.mktime(time.strptime(cred["endDateTime"][:19], "%Y-%m-%dT%H:%M:%S"))
    return round((end - start) / (30 * 86400))


def _uses(record, cred):
    """Is this the secret the Hub (and so the connectors) uses?"""
    if record.get("secretKeyId"):
        return cred.get("keyId") == record["secretKeyId"]
    return bool(record.get("secret")) and cred.get("hint") == record["secret"][:3]


def manage_session(q):
    sess = _session(q.get("sid"))
    if not sess:
        return _expired()
    record = store.load("method2-conn", sess["id"])
    app = graphops.find_app(sess["token"], app_id=record["appId"]) if record else None
    sid = esc(q["sid"])
    note = f"<div class='card'><p>{esc(q['msg'])}</p></div>" if q.get("msg") else ""
    if not app:
        _close(q["sid"])
        return page("The SPN no longer exists", note + "<div class='card'><p>The app registration is not in the tenant any more."
                    " <a href='/'>Back</a></p></div>", PRODUCT)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    rows = []
    for c in sorted(app.get("passwordCredentials") or [], key=lambda c: c.get("startDateTime") or ""):
        used = _uses(record, c)
        status = "<span class='pill FAIL'>EXPIRED</span>" if (c.get("endDateTime") or "") < now else \
                 "<span class='pill OK'>ACTIVE</span>"
        badge = " <span class='pill PARTIAL'>used by cor.</span>" if used else ""
        warn = ("This is the secret the cor. connectors use: they will stop working until a new one is created. "
                if used else "")
        rows.append(
            f"<tr><td>{esc(c.get('displayName') or '—')}{badge}</td><td><code>{esc((c.get('hint') or '') + '…')}</code></td>"
            f"<td><code>{esc((c.get('keyId') or '')[:8])}</code></td><td>{esc((c.get('startDateTime') or '')[:10])}</td>"
            f"<td>{esc((c.get('endDateTime') or '')[:10])}</td><td>{status}</td>"
            f"<td><form method='post' action='/m2/manage/remove-secret' "
            f"onsubmit=\"return confirm('{warn}Remove this secret?')\">"
            f"<input type='hidden' name='sid' value='{sid}'><input type='hidden' name='keyId' value='{esc(c.get('keyId') or '')}'>"
            f"<button class='btn secondary'>Remove</button></form></td></tr>")
    table = ("<table><tr><th>Description</th><th>Value starts</th><th>Key ID</th><th>Created</th><th>Expires</th>"
             "<th>Status</th><th></th></tr>" + "".join(rows) + "</table>") if rows else "<p>No secrets on this app.</p>"
    left = int((sess["expires"] - time.time()) // 60)
    body = (note +
            f"<div class='card'><h2 style='margin-top:0'>Secrets of {esc(app['displayName'])}</h2>"
            f"<p class='muted'>Client ID <code>{esc(app['appId'])}</code>. Every secret on the app is listed, "
            f"including ones created outside cor.</p>{table}</div>"
            "<div class='card'><h2 style='margin-top:0'>Delete the SPN</h2>"
            "<p>Deletes the app registration and its service principal: every permission, the Exchange role and every "
            "secret go with it, and the cor. connectors stop working. Entra keeps it under "
            "<b>App registrations → Deleted applications</b> for 30 days, where it can be restored.</p>"
            "<form method='post' action='/m2/manage/delete-spn' "
            "onsubmit=\"return confirm('Delete this SPN? The cor. connectors stop working.')\">"
            f"<input type='hidden' name='sid' value='{sid}'>"
            "<label><input type='checkbox' name='confirm' value='1' required> I understand the connectors stop working</label>"
            "<p><button class='btn danger'>Delete the SPN</button></p></form></div>"
            "<form method='post' action='/m2/manage/finish'>"
            f"<input type='hidden' name='sid' value='{sid}'>"
            f"<p><button class='btn'>Finish</button> <span class='muted'>drops your token now "
            f"(otherwise in {max(left, 0)} min) and removes cor.'s onboarding app from your tenant</span></p></form>")
    return page("Manage the cor. SPN", body, PRODUCT)


def manage_remove_secret(form):
    sess = _session(form.get("sid"))
    if not sess:
        return _expired()
    record = store.load("method2-conn", sess["id"])
    key_id = form.get("keyId", "")
    app = graphops.find_app(sess["token"], app_id=record["appId"])
    cred = next((c for c in app.get("passwordCredentials") or [] if c.get("keyId") == key_id), None)
    if not cred:
        msg = "That secret is not on the app any more."
    else:
        graphops.remove_secret(sess["token"], app["id"], key_id)
        msg = f"Removed the secret '{cred.get('displayName') or key_id[:8]}'."
        if _uses(record, cred):
            record.update({"secret": None, "secretKeyId": None, "secretExpires": ""})
            store.save("method2-conn", record["id"], record)
            msg += (" It was the one the cor. connectors use: run this connection again with "
                    "'Renew the secret' to give them a new one.")
    return Redirect(f"/m2/manage/session?sid={urllib.parse.quote(form['sid'])}&msg={urllib.parse.quote(msg)}")


def manage_delete_spn(form):
    sess = _session(form.get("sid"))
    if not sess:
        return _expired()
    if form.get("confirm") != "1":
        return Redirect(f"/m2/manage/session?sid={urllib.parse.quote(form['sid'])}"
                        f"&msg={urllib.parse.quote('Tick the confirmation box to delete the SPN.')}")
    record = store.load("method2-conn", sess["id"])
    app = graphops.find_app(sess["token"], app_id=record["appId"])
    steps = []
    if app:
        auth.graph("DELETE", f"/applications/{app['id']}", sess["token"])
        steps.append(f"Deleted '{app['displayName']}' (client ID {app['appId']}) with its service principal, "
                     "permissions, role and secrets. Restorable for 30 days from App registrations → Deleted applications.")
    else:
        steps.append("The app registration was already gone.")
    store.delete("method2-conn", record["id"])
    steps.append("Removed the connection from the Hub.")
    closed = _close(form["sid"])
    if closed:
        steps.append(closed)
    items = "".join(f"<li class='ok'>{esc(t)}</li>" for t in steps)
    return page("The cor. SPN was deleted", f"<div class='card'><ol class='steps'>{items}</ol>"
                                            "<p><a class='btn secondary' href='/'>Back</a></p></div>", PRODUCT)


def manage_finish(form):
    closed = _close(form.get("sid", ""))
    return page("Done", f"<div class='card'><p>Your token was dropped. {esc(closed)}</p>"
                        "<p><a class='btn secondary' href='/'>Back</a></p></div>", PRODUCT)


if __name__ == "__main__":
    serve(8401, {"/": index, "/m2/setup": setup_page, "/m2/review": review_page,
                 "/m2/callback": callback, "/m2/verify": verify_page,
                 "/m2/manage": manage_page, "/m2/manage/session": manage_session},
          {"/m2/start": start, "/m2/manage/start": manage_start,
           "/m2/manage/remove-secret": manage_remove_secret,
           "/m2/manage/delete-spn": manage_delete_spn, "/m2/manage/finish": manage_finish},
          product=PRODUCT)
