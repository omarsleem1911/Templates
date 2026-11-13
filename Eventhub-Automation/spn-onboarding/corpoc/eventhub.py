"""Connect Event Hub: the automated version of eventhub-steps-manual.pdf.

Separate from the Microsoft 365 flow: own process (eventhub_portal.py), own redirect
URI, no Graph code. It reuses only the "cor. onboarding (PoC)" sign-in app.

  1. The admin signs in through the cor. onboarding app and grants it Azure Resource
     Manager access (delegated: COR acts as the admin, within the admin's own RBAC).
  2. The admin deploys the ARM template from the Azure portal (cor.'s form: subscription,
     resource group, region, namespace, event hub, storage account).
  3. COR watches for the deployment in the background, with the admin's sign-in held in
     memory only. When it succeeds COR retrieves the Event Hub and storage connection
     strings and key expiry, creates the Entra ID diagnostic setting (when the admin has
     the role), tests both connections and drops the sign-in.
  4. The Hub page shows the result; "Test connection" re-checks the strings at any time.

PoC: the strings are kept in state/ (git-ignored) and shown on the Hub page.
Production stores them in COR's own secret store instead.
"""

import base64
import datetime
import hashlib
import hmac
import json
import os
import pathlib
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import auth, store
from .web import CORS, Raw, Redirect, esc, page



def _registered_redirect():
    """The sign-in redirect URI. Production: a URI of its own on the onboarding app
    (eventhubRedirectUri, added by `method2_setup.py register`). PoC without access to
    cor.'s tenant: reuse the URI the app already has (the M365 one); this process then
    serves the callback on that address, so the two Hubs cannot run at the same time."""
    rec = store.load("method2", "onboarding-app") or {}
    return (os.environ.get("COR_EH_REDIRECT_URI") or rec.get("eventhubRedirectUri")
            or rec.get("redirectUri") or "http://localhost:8402/eh/callback")


REDIRECT_URI = _registered_redirect()
PORT = urllib.parse.urlparse(REDIRECT_URI).port or 80
CALLBACK_PATH = urllib.parse.urlparse(REDIRECT_URI).path
ARM = "https://management.azure.com"
# Delegated scopes, minimum for this flow: ARM as the signed-in admin (the only ARM scope;
# what it can do is limited by the admin's own Azure roles) plus the sign-in identity.
# No offline_access: Microsoft never issues a refresh token, so once COR discards the one
# access token (or it expires, ~60-90 min) COR cannot act as the admin again without a
# new interactive sign-in.
SCOPES = ["openid", "profile", ARM + "/user_impersonation"]
EH_API = "2024-01-01"
ST_API = "2023-05-01"
KIND = "eventhub-conn"
TAG = "cor-connection-id"
DIAG_NAME = "corlogging"
WATCH_MINUTES = 60
POLL_SECONDS = 15
TEMPLATES = pathlib.Path(__file__).resolve().parent.parent / "eventhub"
# Azure Resource Manager downloads the template itself and refuses localhost, so the
# template link must be public HTTPS: COR_TEMPLATE_URL (a public copy of
# eventhub/azuredeploy.json) or COR_PUBLIC_URL (the Hub's public address). The portal
# form is only read by the admin's browser, so the Hub serves it even on localhost.
PUBLIC_URL = os.environ.get("COR_PUBLIC_URL", f"http://localhost:{PORT}").rstrip("/")


def _settings():
    """eventhub/settings.json (optional): {"templateUrl": "<public HTTPS copy of azuredeploy.json>"}."""
    try:
        return json.loads((TEMPLATES / "settings.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


TEMPLATE_URL = (os.environ.get("COR_TEMPLATE_URL") or _settings().get("templateUrl") or "").strip()

# PDF step 9: Entra ID log categories streamed to the hub (sent only if the tenant offers them).
ENTRA_CATEGORIES = [
    "AuditLogs", "SignInLogs", "NonInteractiveUserSignInLogs", "ServicePrincipalSignInLogs",
    "ManagedIdentitySignInLogs", "ProvisioningLogs", "ADFSSignInLogs", "RiskyUsers", "UserRiskEvents",
    "NetworkAccessTrafficLogs", "RiskyServicePrincipals", "ServicePrincipalRiskEvents",
    "EnrichedOffice365AuditLogs", "MicrosoftGraphActivityLogs", "RemoteNetworkHealthLogs",
    "NetworkAccessAlerts", "NetworkAccessConnectionEvents", "AzureADGraphActivityLogs",
    "MicrosoftServicePrincipalSignInLogs"]
ENTRA_CORE = ["AuditLogs", "SignInLogs", "NonInteractiveUserSignInLogs", "ServicePrincipalSignInLogs",
              "ManagedIdentitySignInLogs", "ProvisioningLogs", "ADFSSignInLogs"]
ACTIVITY_CATEGORIES = ["Administrative", "Security", "Alert", "Recommendation", "Policy"]

PRODUCT = "Event Hub onboarding (PoC)"
PENDING = {}    # sign-in state -> request (one-time)
SESSIONS = {}   # connection id -> admin tokens, memory only, dropped when done or expired
_lock = threading.Lock()


def onboarding_app():
    return store.load("method2", "onboarding-app")


def _page(title, body, step=None):
    return page(title, body, PRODUCT, step=step, section="eventhub")


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


# --- Records ----------------------------------------------------------------------------

def _load(conn_id):
    return store.load(KIND, conn_id) if re.fullmatch(r"[0-9a-f]{16}", conn_id or "") else None


class _Deleted(Exception):
    """The connection's record was deleted while work on it was still running."""


def _update(conn_id, **fields):
    with _lock:
        rec = store.load(KIND, conn_id)
        if rec is None:
            raise _Deleted(conn_id)
        rec.update(fields, updatedAt=_now())
        store.save(KIND, conn_id, rec)
        return rec


def _step(conn_id, kind, text, replace_last=False):
    """Append a progress line (never a secret). replace_last updates a 'waiting' line in place."""
    with _lock:
        rec = store.load(KIND, conn_id)
        if rec is None:
            raise _Deleted(conn_id)
        steps = rec.setdefault("steps", [])
        if replace_last and steps and steps[-1][0] == "wait":
            steps[-1] = [kind, text, _now()[11:]]
        else:
            steps.append([kind, text, _now()[11:]])
        rec["updatedAt"] = _now()
        store.save(KIND, conn_id, rec)


# --- Azure Resource Manager -----------------------------------------------------------

TRANSIENT_STATUS = (408, 429, 500, 502, 503, 504)


def arm(method, path, token, body=None, api=None, attempts=4):
    """An ARM call; temporary failures (dropped connection, timeout, throttling, 5xx)
    are retried with backoff before giving up."""
    url = path if path.startswith("https://") else ARM + path
    if api:
        url += ("&" if "?" in url else "?") + f"api-version={api}"
    for attempt in range(attempts):
        try:
            status, resp = auth.http(method, url, token=token, json_body=body, timeout=60)
        except OSError:  # URLError, ConnectionResetError, timeouts
            if attempt == attempts - 1:
                raise
            time.sleep(2 ** attempt * 2)
            continue
        if status in TRANSIENT_STATUS and attempt < attempts - 1:
            time.sleep(2 ** attempt * 2)
            continue
        if status >= 400:
            raise auth.HttpError(status, resp)
        return resp


def arm_list(path, token, api=None):
    items, url = [], path
    while url:
        resp = arm("GET", url, token, api=api if url == path else None) or {}
        items += resp.get("value", [])
        url = resp.get("nextLink")
    return items


def _token(conn_id):
    """The admin's ARM access token for this connection (no refresh: it is the only one)."""
    sess = SESSIONS.get(conn_id)
    return sess["access"] if sess else None


def _drop_session(conn_id, reason):
    """Discard the admin's access token. The only copy COR has is this in-memory entry
    (nothing is written to disk or logs), so clearing it ends COR's delegated access."""
    sess = SESSIONS.pop(conn_id, None)
    if sess is None:
        return False
    sess.clear()
    try:
        _update(conn_id, signInDiscardedAt=_now(), signInDiscardedReason=reason)
        _step(conn_id, "ok", f"Discarded the admin's Azure sign-in ({reason}). No refresh token was ever issued: "
                             "cor. cannot act as the admin again without a new sign-in.")
    except _Deleted:
        pass  # the record is gone: nothing to note, the sign-in is discarded all the same
    return True


# --- Template, portal link ----------------------------------------------------------------

def template_is_public():
    if TEMPLATE_URL:
        return True
    host = urllib.parse.urlparse(PUBLIC_URL).hostname or ""
    return PUBLIC_URL.startswith("https://") and host not in ("localhost", "127.0.0.1")


def deploy_url(conn_id):
    cid = urllib.parse.quote(conn_id)
    tpl = TEMPLATE_URL or f"{PUBLIC_URL}/eh/template.json?id={cid}"
    ui = f"{PUBLIC_URL}/eh/createUiDefinition.json?id={cid}"
    return ("https://portal.azure.com/#create/Microsoft.Template/uri/" + urllib.parse.quote(tpl, safe="")
            + "/createUIDefinitionUri/" + urllib.parse.quote(ui, safe=""))


def template_route(q):
    tpl = json.loads((TEMPLATES / "azuredeploy.json").read_text(encoding="utf-8"))
    rec = _load(q.get("id", ""))
    if rec:
        tpl["parameters"]["corConnectionId"]["defaultValue"] = rec["id"]
    return Raw(json.dumps(tpl, indent=2), headers=CORS)


def ui_route(q):
    """The portal form, carrying this connection's ID (works with a static public template too)."""
    ui = json.loads((TEMPLATES / "createUiDefinition.json").read_text(encoding="utf-8"))
    rec = _load(q.get("id", ""))
    if rec:
        ui["parameters"]["outputs"]["corConnectionId"] = rec["id"]
        # Azure cannot redirect after a deployment: give the admin the way back, on the form itself.
        back = f"{PUBLIC_URL}/eh/connection?id={rec['id']}"
        ui["parameters"]["config"]["basics"]["description"] += (
            f"\n\nAfter **Create**, go back to [your cor. onboarding page]({back}): it shows the result "
            "as soon as the deployment succeeds.")
    return Raw(json.dumps(ui, indent=2), headers=CORS)


# --- Pages --------------------------------------------------------------------------------

STATE_TEXT = {"signin": ("PENDING", "WAITING FOR SIGN-IN"), "waiting": ("PENDING", "WAITING FOR DEPLOYMENT"),
              "collecting": ("PENDING", "RETRIEVING"), "done": ("OK", "CONNECTED"),
              "failed": ("FAIL", "FAILED"), "expired": ("FAIL", "SIGN-IN EXPIRED"),
              "cancelled": ("FAIL", "CANCELLED")}


def _state(rec):
    return rec.get("state") or ("done" if rec.get("eventHubConnectionString") else "signin")


def _pill(rec):
    cls, text = STATE_TEXT.get(_state(rec), ("PENDING", "—"))
    return f"<span class='pill {cls}'>{text}</span>"


def index(q):
    if not onboarding_app():
        return _page("Set up first", "<p>Run <code>python method2_setup.py register</code> once, then reload.</p>")
    rows = "".join(
        f"<tr><td><b>{esc(r.get('namespace') or '—')}</b><br><span class='muted'>{esc(r.get('eventHub') or r['id'])}</span></td>"
        f"<td>{_pill(r)}</td><td>{esc(r.get('updatedAt') or r['createdAt'])}</td>"
        f"<td style='white-space:nowrap'><a href='/eh/connection?id={esc(r['id'])}'>Open</a> &nbsp; "
        f"{_delete_button(r['id'])}</td></tr>"
        for r in sorted(store.all_records(KIND), key=lambda r: r["createdAt"], reverse=True))
    err = f"<div class='note warn'>{esc(q['msg'])}</div>" if q.get("msg") else ""
    done = f"<div class='note' style='margin-top:24px'>{esc(q['done'])}</div>" if q.get("done") else ""
    body = (
        "<div class='split'><div><p class='eyebrow'>Event Hub integration</p><h1>Stream your Azure logs to cor.</h1>"
        "<p class='lead'>cor. reads your <b>Entra ID</b> logs through an Event Hub deployed in <b>your</b> subscription. "
        "You sign in, fill in one Azure form and approve the deployment: cor. does the rest.</p>"
        "<p class='lead'>Sign in with an account that is <b>Owner</b> or <b>Contributor</b> on the subscription. "
        "To stream the Entra ID logs automatically it also needs <b>Global Administrator</b> or "
        "<b>Security Administrator</b>.</p></div><div>"
        f"<div class='stepcard'><div class='txt'><p class='eyebrow'>Step 1</p><h3>Sign in and authorize</h3>"
        "<p>Sign in with Microsoft and allow cor. to manage Azure resources as you, for this onboarding only.</p></div></div>"
        f"<div class='stepcard'><div class='txt'><p class='eyebrow'>Step 2</p><h3>Deploy to Azure</h3>"
        "<p>The Azure portal opens cor.'s form. Choose the subscription, resource group, region and names, then "
        "<b>Review + create</b>.</p></div></div>"
        f"<div class='stepcard'><div class='txt'><p class='eyebrow'>Step 3</p><h3>cor. connects it</h3>"
        "<p>cor. detects the deployment, retrieves the connection strings, turns on Entra ID log streaming and "
        "tests the connection.</p></div></div>"
        f"<form method='post' action='/eh/start' class='card'>{err}"
        "<label><input type='checkbox' name='entra' value='1' checked> Stream the <b>Entra ID logs</b> to the hub "
        "(diagnostic setting <code>corlogging</code>)</label>"
        "<label><input type='checkbox' name='activity' value='1'> Also stream the <b>activity log of every "
        "subscription</b> the account can manage</label>"
        "<label><input type='checkbox' name='consent' value='1'> <b>Always show the consent screen</b> "
        "<span class='muted'>(demo: Microsoft asks for the permissions even if they were already accepted)</span></label>"
        "<label class='field' style='margin-top:14px'><span>Your tenant domain</span>"
        "<input type='text' name='tenant' placeholder='contoso.onmicrosoft.com'>"
        "<span class='muted' style='display:block;font-weight:400;font-size:13px;margin-top:4px'>"
        "<b>Required for personal Microsoft accounts</b> (outlook.com, hotmail.com, live.com): Microsoft only lets "
        "them sign in through their tenant's own page. Find it in the Azure portal under <b>Microsoft Entra ID → "
        "Overview → Primary domain</b>. Optional for work or school accounts.</span></label>"
        "<div class='actions'><span></span><button class='btn ms right'>Sign in with Microsoft</button></div></form>"
        "</div></div>"
        + done
        + (f"<div style='display:flex;align-items:center;justify-content:space-between;gap:12px;margin-top:40px'>"
           f"<h2 id='connections' style='margin:0'>Event Hub connections</h2>"
           f"<form method='post' action='/eh/delete-all' style='margin:0' onsubmit=\"return confirm("
           f"'Delete ALL connections? Running onboardings are stopped and their sign-in discarded. "
           f"Azure resources are not touched.')\"><button class='btn secondary' style='padding:6px 14px'>Delete all"
           f"</button></form></div><table><tr><th>Namespace</th>"
           f"<th>Status</th><th>Last change</th><th></th></tr>{rows}</table>" if rows else ""))
    return _page("Connect Event Hub", body, step=10)


def _prompt(force_consent):
    """select_account: always show the account picker. consent: always show the permissions
    screen, even if the admin already accepted them (Microsoft takes one prompt value)."""
    return "consent" if force_consent else "select_account"


def start(form):
    app = onboarding_app()
    if not app:
        return Redirect("/")
    conn_id = secrets.token_hex(8)
    tenant = (form.get("tenant") or "").strip() or "organizations"
    store.save(KIND, conn_id, {"id": conn_id, "createdAt": _now(), "updatedAt": _now(), "state": "signin",
                               "options": {"entra": form.get("entra") == "1", "activity": form.get("activity") == "1",
                                           "forceConsent": form.get("consent") == "1"},
                               "steps": []})
    verifier, challenge = auth.pkce()
    state = secrets.token_urlsafe(16)
    PENDING[state] = {"id": conn_id, "tenant": tenant, "verifier": verifier}
    return Redirect(auth.authorize_url(tenant, app["appId"], REDIRECT_URI, SCOPES, state, challenge,
                                       prompt=_prompt(form.get("consent") == "1")))


def callback(q):
    req = PENDING.pop(q.get("state", ""), None)
    if req is None:
        return 400, _page("Unknown request", "<p>Start again from the <a href='/'>start page</a>.</p>")
    if q.get("error"):
        _update(req["id"], state="failed")
        _step(req["id"], "fail", f"Microsoft sign-in was not completed: {q['error']}")
        return Redirect(f"/eh/connection?id={req['id']}")
    if not _load(req["id"]):
        return Redirect("/?done=" + urllib.parse.quote("That connection was deleted: start a new one."))
    app = onboarding_app()
    try:
        tok = auth.redeem_code(req["tenant"], app["appId"], q["code"], REDIRECT_URI, req["verifier"], SCOPES)
    except auth.HttpError as exc:
        _update(req["id"], state="failed")
        _step(req["id"], "fail", f"Sign-in failed — {exc}")
        return Redirect(f"/eh/connection?id={req['id']}")
    c = auth.claims(tok["access_token"])
    who = c.get("upn") or c.get("unique_name") or c.get("preferred_username") or "the admin"
    expires = time.time() + int(tok.get("expires_in", 3600))
    SESSIONS[req["id"]] = {"access": tok["access_token"], "tenant": c.get("tid") or req["tenant"],
                           "until": min(time.time() + WATCH_MINUTES * 60, expires - 120)}
    minutes = int((SESSIONS[req["id"]]["until"] - time.time()) // 60)
    tok.clear()
    _update(req["id"], state="waiting", tenant=c.get("tid"), signedInAs=who)
    _step(req["id"], "ok", f"Signed in as {who}; Azure Resource Manager access granted for this onboarding "
                           f"(one access token, memory only, used for at most {minutes} minutes; no refresh token).")
    _step(req["id"], "wait", "Waiting for the deployment in the Azure portal…")
    threading.Thread(target=watch, args=(req["id"],), daemon=True).start()
    return Redirect(f"/eh/connection?id={req['id']}")


def connection(q):
    rec = _load(q.get("id", ""))
    if not rec:
        return 404, _page("Unknown connection", "<p>Unknown connection. <a href='/'>Back</a></p>")
    state = _state(rec)
    steps = "".join(f"<li class='{'warn' if s[0] == 'wait' else s[0]}'><span class='muted'>{esc(s[2] if len(s) > 2 else '')}</span> "
                    f"{esc(s[1])}</li>" for s in rec.get("steps", []))
    progress = f"<h2 style='margin-top:0'>Progress {_pill(rec)}</h2><ul class='steps' id='steps'>{steps or '<li>—</li>'}</ul>"
    # Waiting with no watcher (e.g. the Hub restarted): the sign-in is gone, offer to sign in again.
    live = state in ("waiting", "collecting") and rec["id"] in SESSIONS
    poll = ("<script>setInterval(async()=>{try{const r=await fetch('/eh/status?id=" + rec["id"] + "');"
            "const s=await r.json();if(s.updatedAt!=='" + rec.get("updatedAt", "") + "')location.reload();}catch(e){}},4000)</script>"
            if live else "")
    if state == "done":
        return _result_page(rec, progress, q.get("msg"))
    deploy = ""
    if state in ("waiting", "collecting"):
        warn = ("" if template_is_public() else
                "<div class='note warn'>The template is served from this local Hub: the portal form loads, but Azure "
                "refuses to deploy a template from localhost. Set <code>COR_TEMPLATE_URL</code> to a public copy of "
                "<code>eventhub/azuredeploy.json</code> and restart. For a quick test: in the portal, <b>Edit template</b>, "
                "change any whitespace, <b>Save</b>.</div>")
        deploy = (f"<div class='stepcard'><div class='txt'><p class='eyebrow'>Step 2</p><h3>Deploy to Azure</h3>"
                  "<p>Fill in cor.'s form and click <b>Review + create</b>, then <b>Create</b>. Keep this page open: "
                  "it updates by itself.</p>"
                  f"<p style='margin-top:14px'><a class='btn' target='_blank' rel='noopener' href='{esc(deploy_url(rec['id']))}'>"
                  "Deploy to Azure</a></p></div></div>" + warn)
    retry = ("<form method='post' action='/eh/cancel' class='actions'>"
             f"<input type='hidden' name='id' value='{esc(rec['id'])}'><a class='btn secondary' href='/'>Back</a>"
             "<button class='btn secondary right'>Cancel and discard the sign-in</button></form>" if live else
             "<form method='post' action='/eh/resume' class='actions'>"
             f"<input type='hidden' name='id' value='{esc(rec['id'])}'><a class='btn secondary' href='/'>Back</a>"
             "<button class='btn ms right'>Sign in again and continue</button></form>")
    body = (f"<div class='split'><div><p class='eyebrow'>Connection {esc(rec['id'])}</p><h1>Connecting your Event Hub</h1>"
            "<p class='lead'>cor. watches for the deployment and connects it as soon as it succeeds. "
            "No keys are copied by hand.</p></div><div>"
            f"{deploy}<div class='card'>{progress}</div>{retry}</div></div>{poll}")
    title = {"waiting": "⏳ Waiting for deployment", "collecting": "⏳ Connecting Event Hub",
             "failed": "✖ Event Hub onboarding failed", "expired": "✖ Sign-in expired",
             "cancelled": "Event Hub onboarding cancelled",
             "stale": "Sign in again to continue"}.get(
        "stale" if state in ("waiting", "collecting") and not live else state, "Connecting your Event Hub")
    return _page(title, body, step=50)


def resume(form):
    """Sign in again for an existing connection (e.g. the first sign-in expired)."""
    rec = _load(form.get("id", ""))
    app = onboarding_app()
    if not rec or not app:
        return Redirect("/")
    verifier, challenge = auth.pkce()
    state = secrets.token_urlsafe(16)
    PENDING[state] = {"id": rec["id"], "tenant": rec.get("tenant") or "organizations", "verifier": verifier}
    return Redirect(auth.authorize_url(PENDING[state]["tenant"], app["appId"], REDIRECT_URI, SCOPES, state, challenge,
                                       prompt=_prompt((rec.get("options") or {}).get("forceConsent"))))


def _delete(conn_id):
    """Delete one connection: discard any sign-in it holds, then its record (cor.'s copy of the
    connection strings goes with it). Azure resources and settings are not touched."""
    _drop_session(conn_id, "connection deleted")
    for state, req in list(PENDING.items()):
        if req["id"] == conn_id:
            PENDING.pop(state, None)
    with _lock:
        store.delete(KIND, conn_id)


def delete(form):
    rec = _load(form.get("id", ""))
    if rec:
        _delete(rec["id"])
        msg = f"Deleted connection {rec['id']}" + (f" ({rec['namespace']})" if rec.get("namespace") else "") + "."
    else:
        msg = "That connection was already deleted."
    return Redirect("/?done=" + urllib.parse.quote(msg))


def delete_all(_form):
    recs = store.all_records(KIND)
    for r in recs:
        _delete(r["id"])
    return Redirect("/?done=" + urllib.parse.quote(f"Deleted all {len(recs)} connection(s)."))


DELETE_NOTE = ("Deletes cor.'s record of this connection, including its saved connection strings. The Event Hub, "
               "storage account and Entra ID setting in Azure are not touched.")


def _delete_button(conn_id, label="Delete", cls="btn secondary"):
    return (f"<form method='post' action='/eh/delete' style='margin:0;display:inline' "
            f"onsubmit=\"return confirm('Delete connection {esc(conn_id)}? {DELETE_NOTE}')\">"
            f"<input type='hidden' name='id' value='{esc(conn_id)}'>"
            f"<button class='{cls}' style='padding:6px 14px'>{esc(label)}</button></form>")


def cancel(form):
    """Stop the onboarding and discard the admin's sign-in now."""
    rec = _load(form.get("id", ""))
    if rec and rec["id"] in SESSIONS:
        _update(rec["id"], state="cancelled")
        _drop_session(rec["id"], "cancelled by the admin")
    return Redirect(f"/eh/connection?id={rec['id']}" if rec else "/")


def status(q):
    """Progress for the page's auto-refresh. Never contains a secret."""
    rec = _load(q.get("id", "")) or {}
    return Raw(json.dumps({"state": rec.get("state"), "updatedAt": rec.get("updatedAt"),
                           "steps": rec.get("steps", [])}))


# --- Background: watch the deployment, then retrieve and configure -------------------------

def watch(conn_id):
    rec = store.load(KIND, conn_id)
    try:
        while time.time() < (SESSIONS.get(conn_id) or {}).get("until", 0):
            try:
                token = _token(conn_id)
                found = _find(token, conn_id) if token else None
            except OSError as exc:  # network still down after arm()'s retries: keep watching
                _step(conn_id, "wait", f"Temporary network problem ({type(exc).__name__}); still watching…",
                      replace_last=True)
                time.sleep(POLL_SECONDS)
                continue
            if found and conn_id in SESSIONS:
                _update(conn_id, state="collecting")
                _step(conn_id, "ok", f"Deployment '{found['deployment']}' succeeded in resource group "
                                     f"{found['rg'].split('/')[-1]}.", replace_last=True)
                collect(token, conn_id, found, rec["options"])
                return
            time.sleep(POLL_SECONDS)
        if SESSIONS.get(conn_id):
            _update(conn_id, state="expired")
            _step(conn_id, "fail", "No succeeded deployment seen while the sign-in was valid. Deploy, then sign in "
                                   "again to continue.", replace_last=True)
            _drop_session(conn_id, "time limit reached")
    except _Deleted:
        pass  # deleted by the admin: stop quietly (finally discards the sign-in)
    except _DeploymentFailed as exc:
        _fail(conn_id, str(exc))
    except auth.HttpError as exc:
        _fail(conn_id, f"Azure refused a request — {exc}")
    except Exception as exc:  # report, never crash the thread silently
        _fail(conn_id, f"Unexpected error: {type(exc).__name__}: {exc}")
    finally:
        rec = store.load(KIND, conn_id) or {}
        _drop_session(conn_id, {"done": "onboarding complete", "failed": "onboarding failed"}.get(
            rec.get("state"), "watcher stopped"))


def _fail(conn_id, text):
    """Record a failure, unless the admin cancelled meanwhile (then it stays "cancelled")."""
    rec = store.load(KIND, conn_id)
    if rec is None or _state(rec) == "cancelled":
        return
    _update(conn_id, state="failed")
    _step(conn_id, "fail", text, replace_last=True)


class _DeploymentFailed(Exception):
    pass


def _find(token, conn_id):
    """The succeeded deployment of this connection, or None while it is not there yet."""
    flt = urllib.parse.quote(f"tagName eq '{TAG}' and tagValue eq '{conn_id}'")
    for s in arm_list("/subscriptions", token, api="2022-12-01"):
        if s.get("state") != "Enabled":
            continue
        res = {r["type"].lower(): r for r in
               arm_list(f"/subscriptions/{s['subscriptionId']}/resources?$filter={flt}", token, api="2021-04-01")}
        ns, st = res.get("microsoft.eventhub/namespaces"), res.get("microsoft.storage/storageaccounts")
        if not ns:
            continue
        rg = ns["id"].split("/providers/")[0]
        deps = [d for d in arm_list(f"{rg}/providers/Microsoft.Resources/deployments", token, api="2021-04-01")
                if ((d.get("properties") or {}).get("parameters") or {}).get("corConnectionId", {}).get("value") == conn_id]
        deps.sort(key=lambda d: d["properties"].get("timestamp") or "", reverse=True)
        dep = deps[0] if deps else None
        state = dep["properties"].get("provisioningState") if dep else None
        if state in ("Failed", "Canceled"):
            raise _DeploymentFailed(f"The deployment '{dep['name']}' {state.lower()}: fix it in the Azure portal "
                                    "and deploy again, then sign in again here.")
        if state == "Succeeded" and st:
            outputs = {k: v.get("value") for k, v in (dep["properties"].get("outputs") or {}).items()}
            return {"subscription": s, "rg": rg, "ns": ns, "st": st, "outputs": outputs, "deployment": dep["name"]}
        _step(conn_id, "wait", f"Deployment {dep['name'] if dep else ''} in progress "
                               f"({state or 'starting'})…", replace_last=True)
    return None


def collect(token, conn_id, found, options):
    ns, st, outputs = found["ns"], found["st"], found["outputs"]
    eh_name = outputs.get("eventHubName") or next(
        (h["name"] for h in arm_list(f"{ns['id']}/eventhubs", token, api=EH_API)), None)
    policy = outputs.get("sharedAccessKeyName") or "corehSAS"
    container = outputs.get("containerName") or next(
        (x["name"] for x in arm_list(f"{st['id']}/blobServices/default/containers", token, api=ST_API)), None)
    rule_id = f"{ns['id']}/authorizationRules/{policy}"

    eh_keys = arm("POST", f"{rule_id}/listKeys", token, api=EH_API)
    st_keys = arm("POST", f"{st['id']}/listKeys", token, api=ST_API)
    st_props = arm("GET", st["id"], token, api=ST_API).get("properties") or {}
    key1 = st_keys["keys"][0]
    storage_cs = (f"DefaultEndpointsProtocol=https;AccountName={st['name']};"
                  f"AccountKey={key1['value']};EndpointSuffix=core.windows.net")
    _update(conn_id, subscriptionId=found["subscription"]["subscriptionId"],
            subscriptionName=found["subscription"].get("displayName"), resourceGroup=found["rg"].split("/")[-1],
            region=ns.get("location"), namespace=ns["name"], eventHub=eh_name, sharedAccessKeyName=policy,
            consumerGroup=outputs.get("consumerGroup") or "$Default", storageAccount=st["name"], container=container,
            eventHubConnectionString=eh_keys["primaryConnectionString"], storageConnectionString=storage_cs,
            expiry=_expiry(key1, st_props), retrievedAt=_now())
    _step(conn_id, "ok", f"Retrieved the Event Hub connection string (policy {policy}) and the storage "
                         f"connection string (account {st['name']}, key1).")

    try:  # shape of the hub, for the result page
        hub = arm("GET", f"{ns['id']}/eventhubs/{eh_name}", token, api=EH_API).get("properties") or {}
        _update(conn_id, eventHubDetails={
            "tier": (ns.get("sku") or {}).get("name"), "partitions": hub.get("partitionCount"),
            "retentionHours": (hub.get("retentionDescription") or {}).get("retentionTimeInHours")})
    except auth.HttpError:
        pass

    _set_diag(conn_id, "entra", {"status": "off"})
    _set_diag(conn_id, "activity", {"status": "off"})
    if options.get("entra"):
        _entra_diagnostics(token, conn_id, rule_id, eh_name)
    if options.get("activity"):
        _activity_diagnostics(token, conn_id, rule_id, eh_name)

    _drop_session(conn_id, "connection strings retrieved")  # before the test: it needs no Azure access
    rec = run_test(conn_id)
    _update(conn_id, state="done")
    _step(conn_id, "ok" if rec["test"]["ok"] else "warn",
          "Connection test passed: the connector can use these strings." if rec["test"]["ok"]
          else "Connected, but the connection test failed: see the test result.")


def _expiry(key1, st_props):
    """Key expiry, as Azure defines it. Event Hubs SAS policy keys never expire; storage keys
    expire only when the account has a key expiration policy (then Azure flags them after
    creation + period; they keep working until rotated)."""
    created = key1.get("creationTime") or ((st_props.get("keyCreationTime") or {}).get("key1"))
    days = (st_props.get("keyPolicy") or {}).get("keyExpirationPeriodInDays")
    expires = None
    if created and days:
        start = datetime.datetime.strptime(created[:19], "%Y-%m-%dT%H:%M:%S")
        expires = (start + datetime.timedelta(days=int(days))).strftime("%Y-%m-%d")
    return {"eventHub": None, "storageKeyCreated": (created or "")[:10] or None,
            "storageKeyPolicyDays": days, "storageKeyExpires": expires}


def _set_diag(conn_id, key, value):
    with _lock:
        rec = store.load(KIND, conn_id)
        if rec is None:
            raise _Deleted(conn_id)
        rec.setdefault("diagnostics", {})[key] = value
        store.save(KIND, conn_id, rec)


def _entra_diagnostics(token, conn_id, rule_id, eh_name):
    """PDF step 9: Entra ID -> Diagnostic settings -> stream to the event hub."""
    try:
        offered = {x["name"] for x in arm_list("/providers/microsoft.aadiam/diagnosticSettingsCategories", token,
                                               api="2017-04-01")
                   if (x.get("properties") or {}).get("categoryType", "Logs") == "Logs"}
    except auth.HttpError:
        offered = set()
    wanted = [n for n in ENTRA_CATEGORIES if not offered or n in offered]

    def put(categories):
        arm("PUT", f"/providers/microsoft.aadiam/diagnosticSettings/{DIAG_NAME}", token, api="2017-04-01", body={
            "properties": {"eventHubAuthorizationRuleId": rule_id, "eventHubName": eh_name,
                           "logs": [{"category": n, "enabled": True} for n in categories]}})

    try:
        put(wanted)
        _set_diag(conn_id, "entra", {"status": "on", "setting": DIAG_NAME, "categories": wanted})
        _step(conn_id, "ok", f"Entra ID diagnostic setting '{DIAG_NAME}' streams {len(wanted)} log categories to the hub.")
    except auth.HttpError as exc:
        if exc.status == 403:
            _set_diag(conn_id, "entra", {"status": "failed", "setting": DIAG_NAME, "categories": [],
                                         "reason": "The account is not Global or Security Administrator."})
            _step(conn_id, "warn", "Entra ID logs not streamed: the account is not Global or Security Administrator. "
                                   "A Global Administrator can sign in again to add it.")
            return
        core = [n for n in ENTRA_CORE if n in wanted]
        try:
            put(core)
            _set_diag(conn_id, "entra", {"status": "partial", "setting": DIAG_NAME, "categories": core,
                                         "refused": [n for n in wanted if n not in core], "reason": str(exc)})
            _step(conn_id, "warn", f"Entra ID diagnostic setting '{DIAG_NAME}' streams the {len(core)} core categories; "
                                   f"the licence-dependent ones were refused ({exc}).")
        except auth.HttpError as exc2:
            _set_diag(conn_id, "entra", {"status": "failed", "setting": DIAG_NAME, "categories": [], "reason": str(exc2)})
            _step(conn_id, "fail", f"Entra ID diagnostic setting not created — {exc2}")


def _activity_diagnostics(token, conn_id, rule_id, eh_name):
    """The PDF's `az monitor diagnostic-settings subscription create` loop."""
    done, failed = [], []
    for s in arm_list("/subscriptions", token, api="2022-12-01"):
        if s.get("state") != "Enabled":
            continue
        try:
            arm("PUT", f"/subscriptions/{s['subscriptionId']}/providers/Microsoft.Insights/diagnosticSettings/{DIAG_NAME}",
                token, api="2021-05-01-preview", body={
                    "properties": {"eventHubAuthorizationRuleId": rule_id, "eventHubName": eh_name,
                                   "logs": [{"category": n, "enabled": True} for n in ACTIVITY_CATEGORIES]}})
            done.append(s.get("displayName") or s["subscriptionId"])
        except auth.HttpError as exc:
            failed.append(f"{s.get('displayName') or s['subscriptionId']} ({exc})")
    _set_diag(conn_id, "activity", {"status": "on" if done else "failed", "setting": DIAG_NAME,
                                    "categories": ACTIVITY_CATEGORIES, "subscriptions": done, "failed": failed})
    if done:
        _step(conn_id, "ok", f"Activity log streams to the hub from {len(done)} subscription(s): {', '.join(done)}.")
    for f in failed:
        _step(conn_id, "warn", f"Activity log setting not created for {f}.")


# --- Connection test (uses only the connection strings, like the connector) ----------------

def _parse_cs(cs):
    return dict(part.split("=", 1) for part in cs.split(";") if "=" in part)


def _request(method, url, headers, timeout=20):
    req = urllib.request.Request(url, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def test_eventhub(cs, eh_name):
    """GET the event hub with a SAS token signed by the policy key."""
    p = _parse_cs(cs)
    host = urllib.parse.urlparse(p["Endpoint"]).hostname
    uri = urllib.parse.quote_plus(f"https://{host}/{eh_name}")
    expiry = str(int(time.time()) + 300)
    sig = base64.b64encode(hmac.new(p["SharedAccessKey"].encode(), f"{uri}\n{expiry}".encode(),
                                    hashlib.sha256).digest()).decode()
    token = (f"SharedAccessSignature sr={uri}&sig={urllib.parse.quote_plus(sig)}"
             f"&se={expiry}&skn={p['SharedAccessKeyName']}")
    status, body = _request("GET", f"https://{host}/{eh_name}?api-version=2014-01&timeout=60",
                            {"Authorization": token})
    if status == 200:
        parts = re.search(r"<PartitionCount>(\d+)</PartitionCount>", body)
        return True, f"Reached {host}/{eh_name} with policy {p['SharedAccessKeyName']}" + (
            f" ({parts.group(1)} partitions)." if parts else ".")
    return False, f"Event Hubs answered HTTP {status}: {_brief(body)}"


def test_storage(cs, container):
    """GET the checkpoint container's properties, signed with the account key (Shared Key)."""
    p = _parse_cs(cs)
    account, key = p["AccountName"], base64.b64decode(p["AccountKey"])
    date = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime())
    version = "2021-08-06"
    to_sign = ("GET\n" + "\n" * 11 + f"x-ms-date:{date}\nx-ms-version:{version}\n"
               f"/{account}/{container}\nrestype:container")
    sig = base64.b64encode(hmac.new(key, to_sign.encode(), hashlib.sha256).digest()).decode()
    status, body = _request("GET", f"https://{account}.blob.{p.get('EndpointSuffix', 'core.windows.net')}/"
                                   f"{container}?restype=container",
                            {"x-ms-date": date, "x-ms-version": version, "Authorization": f"SharedKey {account}:{sig}"})
    if status == 200:
        return True, f"Reached container {container} in storage account {account}."
    return False, f"Storage answered HTTP {status}: {_brief(body)}"


def _brief(body):
    text = re.sub(r"<[^>]+>", " ", body or "")
    return re.sub(r"\s+", " ", text).strip()[:200] or "no details"


def run_test(conn_id):
    rec = store.load(KIND, conn_id)
    results = []
    for name, fn, args in (("Event Hub", test_eventhub, (rec["eventHubConnectionString"], rec["eventHub"])),
                           ("Storage", test_storage, (rec["storageConnectionString"], rec["container"]))):
        try:
            ok, detail = fn(*args)
        except Exception as exc:
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        results.append({"name": name, "ok": ok, "detail": detail})
    return _update(conn_id, test={"ok": all(r["ok"] for r in results), "at": _now(), "results": results})


def test_route(form):
    rec = _load(form.get("id", ""))
    if not rec or not rec.get("eventHubConnectionString"):
        return Redirect("/")
    run_test(rec["id"])
    return Redirect(f"/eh/connection?id={rec['id']}")


# --- Result ---------------------------------------------------------------------------------

# What each streamed category contains, for the result page.
CATEGORY_TEXT = {
    "AuditLogs": "Directory changes (users, groups, apps, roles)",
    "SignInLogs": "Interactive user sign-ins",
    "NonInteractiveUserSignInLogs": "Sign-ins apps make for a user (token refresh)",
    "ServicePrincipalSignInLogs": "App and service principal sign-ins",
    "ManagedIdentitySignInLogs": "Managed identity sign-ins",
    "ProvisioningLogs": "User provisioning to and from other systems",
    "ADFSSignInLogs": "Sign-ins through AD FS (Connect Health)",
    "RiskyUsers": "Users flagged at risk (ID Protection, P2)",
    "UserRiskEvents": "Risk detections on users (ID Protection, P2)",
    "NetworkAccessTrafficLogs": "Global Secure Access traffic",
    "RiskyServicePrincipals": "Apps flagged at risk (Workload ID)",
    "ServicePrincipalRiskEvents": "Risk detections on apps (Workload ID)",
    "EnrichedOffice365AuditLogs": "Microsoft 365 audit, enriched (Global Secure Access)",
    "MicrosoftGraphActivityLogs": "Every Microsoft Graph API request",
    "RemoteNetworkHealthLogs": "Remote network health (Global Secure Access)",
    "NetworkAccessAlerts": "Global Secure Access alerts",
    "NetworkAccessConnectionEvents": "Global Secure Access connections",
    "AzureADGraphActivityLogs": "Every legacy Azure AD Graph request",
    "MicrosoftServicePrincipalSignInLogs": "Sign-ins by Microsoft's own service principals",
    "Administrative": "Create, update, delete of Azure resources",
    "Security": "Microsoft Defender for Cloud alerts",
    "Alert": "Azure Monitor alerts fired",
    "Recommendation": "Azure Advisor recommendations",
    "Policy": "Azure Policy evaluations and effects",
}


def _pill_text(ok, yes="WORKING", no="NOT WORKING"):
    return f"<span class='pill {'OK' if ok else 'FAIL'}'>{yes if ok else no}</span>"


def _card(title, body, badge=""):
    return (f"<section class='card' style='margin:0'><h2 style='margin:0 0 12px;font-size:16px'>{esc(title)} {badge}</h2>"
            f"{body}</section>")


def _rows(pairs):
    return ("<table>" + "".join(f"<tr><th style='width:40%'>{esc(k)}</th><td>{v}</td></tr>" for k, v in pairs)
            + "</table>")


def _small(text):
    return f"<div class='muted' style='font-size:12.5px'>{text}</div>"


def _secret(value, marker):
    """The value with its key masked, and a Show toggle for the full value."""
    head = value.split(marker)[0] + marker if marker in value else ""
    return (f"<code>{esc(head)}••••••••</code><details style='margin-top:2px'><summary style='margin-top:4px'>Show</summary>"
            f"<code style='display:block;margin-top:6px'>{esc(value)}</code></details>")


def _categories(names):
    return ("<table>" + "".join(f"<tr><td style='width:46%'><code>{esc(n)}</code></td>"
                                f"<td class='muted'>{esc(CATEGORY_TEXT.get(n, ''))}</td></tr>" for n in names)
            + "</table>")


def _result_page(rec, progress, msg=None):
    exp = rec.get("expiry") or {}
    test = rec.get("test") or {}
    diag = rec.get("diagnostics") or {}
    hub = rec.get("eventHubDetails") or {}
    entra, activity = diag.get("entra") or {}, diag.get("activity") or {}
    parts = hub.get("partitions") or next((m.group(1) for r in test.get("results", [])
                                           for m in [re.search(r"\((\d+) partitions\)", r["detail"])] if m), None)
    entra_on = entra.get("status") in ("on", "partial")
    entra_off_text = "FAILED" if entra.get("status") == "failed" else "OFF"

    # Header: everything that matters, in one line.
    head = (f"<p class='eyebrow'>Connection {esc(rec['id'])}</p>"
            "<h1 style='margin-bottom:10px'>Your Event Hub is connected</h1>"
            f"<p style='margin:0 0 6px;display:flex;flex-wrap:wrap;gap:8px 18px;align-items:center'>"
            f"<span>Status {_pill_text(True, 'CONNECTED')}</span>"
            f"<span>Connection test {_pill_text(test.get('ok'))}</span>"
            f"<span>Entra ID logs {_pill_text(entra_on, 'ON', entra_off_text)}</span>"
            f"<span class='muted'>Retrieved {esc(rec.get('retrievedAt') or rec.get('updatedAt'))}</span></p>"
            "<p class='muted' style='margin:0 0 22px;font-size:13.5px'>cor. retrieved everything below itself. PoC: "
            "the connection strings are shown here; in production they go straight to cor.'s secret store.</p>")

    resources = _card("Azure resources", _rows([
        ("Subscription", esc(rec.get("subscriptionName") or rec["subscriptionId"]) + _small(esc(rec["subscriptionId"]))),
        ("Resource group", f"<code>{esc(rec['resourceGroup'])}</code>"),
        ("Region", esc(rec.get("region") or "—")),
        ("Event Hubs namespace", f"<code>{esc(rec['namespace'])}</code>"
         + (_small(f"{esc(hub['tier'])} tier") if hub.get("tier") else "")),
        ("Event hub", f"<code>{esc(rec['eventHub'])}</code>"
         + _small(" · ".join(x for x in (f"{parts} partitions" if parts else "",
                                         f"{hub['retentionHours']} h retention" if hub.get("retentionHours") else "") if x))),
        ("Consumer group", f"<code>{esc(rec['consumerGroup'])}</code>"),
        ("Storage account", f"<code>{esc(rec['storageAccount'])}</code>" + _small("Holds the connector's checkpoints")),
        ("Container", f"<code>{esc(rec['container'])}</code>"),
    ]))

    if exp.get("storageKeyExpires"):
        st_exp = (f"<b>{esc(exp['storageKeyExpires'])}</b>"
                  + _small(f"{esc(str(exp['storageKeyPolicyDays']))}-day expiration policy: Azure flags the key then; "
                           "it keeps working until rotated."))
    else:
        st_exp = "No expiration policy" + _small("Valid until rotated.")
    credentials = _card("Connector credentials", (
        "<h3 style='font-size:14px;margin:0 0 6px'>Event Hub</h3>" + _rows([
            ("Shared access policy", f"<code>{esc(rec['sharedAccessKeyName'])}</code>" + _small("Manage, Send, Listen")),
            ("Key expires", "Never" + _small("SAS policy keys are valid until regenerated.")),
            ("Connection string", _secret(rec["eventHubConnectionString"], "SharedAccessKey=")),
        ]) + "<h3 style='font-size:14px;margin:18px 0 6px'>Storage (checkpoints)</h3>" + _rows([
            ("Key", "key1" + _small(f"Created {esc(exp.get('storageKeyCreated') or '—')}")),
            ("Key expires", st_exp),
            ("Connection string", _secret(rec["storageConnectionString"], "AccountKey=")),
        ])))

    results = "".join(f"<tr><th style='width:22%'>{esc(r['name'])}</th><td style='width:24%'>{_pill_text(r['ok'])}</td>"
                      f"<td>{esc(r['detail'])}</td></tr>" for r in test.get("results", []))
    testing = _card("Connection test", (
        "<p class='muted' style='margin:0 0 8px;font-size:13.5px'>Uses only the two connection strings, as the "
        f"connector does.</p><table>{results}</table>"
        "<form method='post' action='/eh/test' style='margin-top:14px;display:flex;align-items:center;gap:14px;flex-wrap:wrap'>"
        f"<input type='hidden' name='id' value='{esc(rec['id'])}'><button class='btn'>Test connection</button>"
        f"<span class='muted' style='font-size:13px'>Last tested {esc(test.get('at') or 'never')}</span></form>"),
        _pill_text(test.get("ok")))

    if entra_on:
        entra_html = (f"<p style='margin:0 0 8px'>Diagnostic setting <code>{esc(entra.get('setting', DIAG_NAME))}</code> "
                      f"streams <b>{len(entra.get('categories', []))}</b> log categories to "
                      f"<code>{esc(rec['eventHub'])}</code>:</p>" + _categories(entra.get("categories", []))
                      + (f"<p class='muted'>Refused by the tenant's licence: {esc(', '.join(entra['refused']))}</p>"
                         if entra.get("refused") else ""))
    elif not entra:
        entra_html = "<p class='muted' style='margin:0'>Not recorded for this connection.</p>"
    else:
        entra_html = f"<p class='muted' style='margin:0'>{esc(entra.get('reason') or 'Not requested for this connection.')}</p>"
    if activity.get("status") == "on":
        activity_html = (f"<p style='margin:0 0 8px'>From {len(activity['subscriptions'])} subscription(s): "
                         f"{esc(', '.join(activity['subscriptions']))}</p>" + _categories(activity["categories"]))
    else:
        activity_html = "<p class='muted' style='margin:0'>Off: not requested for this connection.</p>"
    logs = _card("Log streaming", (
        f"<h3 style='font-size:14px;margin:0 0 6px'>Entra ID {_pill_text(entra_on, 'ON', entra_off_text)}</h3>{entra_html}"
        f"<h3 style='font-size:14px;margin:18px 0 6px'>Azure activity log "
        f"{_pill_text(activity.get('status') == 'on', 'ON', 'OFF')}</h3>{activity_html}"))

    note = f"<div class='note'>{esc(msg)}</div>" if msg else ""
    grid = ("<div style='display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,430px),1fr));gap:16px;"
            f"align-items:start'><div style='display:grid;gap:16px'>{resources}{testing}</div>"
            f"<div style='display:grid;gap:16px'>{credentials}{logs}</div></div>")
    timeline = ("<details class='card' style='margin-top:16px'><summary style='margin:0'>Onboarding timeline</summary>"
                f"<div style='margin-top:10px'>{progress}</div></details>")
    actions = ("<div class='actions'><a class='btn secondary' href='/'>Back to connections</a>"
               f"<span class='right'>{_delete_button(rec['id'], 'Delete this connection')}</span></div>")
    # The title shows in the browser tab: make the finished state easy to spot among the portal tabs.
    title = "✓ Event Hub connected" if test.get("ok") else "⚠ Event Hub connected, test failing"
    return _page(title, head + note + grid + timeline + actions, step=100)


GET_ROUTES = {"/": index, "/eh": index, CALLBACK_PATH: callback, "/eh/connection": connection,
              "/eh/status": status, "/eh/template.json": template_route, "/eh/createUiDefinition.json": ui_route}
POST_ROUTES = {"/eh/start": start, "/eh/resume": resume, "/eh/test": test_route, "/eh/cancel": cancel,
               "/eh/delete": delete, "/eh/delete-all": delete_all}
