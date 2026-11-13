"""Onboard Azure: discovery-driven, multi-region log collection (the 8-screen wizard).

  1. Sign in & grant permissions: the admin signs in through the cor. onboarding app
     (delegated Azure Resource Manager access, one access token, memory only, no refresh token).
  2. Scan: subscriptions, regions, every resource (Resource Graph) and its current logging
     state (corpoc/discovery.py, the port of the team's az_services_discovery_v4.js).
  3. Discovery results, 4. Select resources: predefined categories are auto-selected;
     the admin can add or remove categories, subscriptions and single resources.
  5. Event Hub plan: one namespace + one event hub per region of the selected resources,
     one shared storage account with one checkpoint container per region. Names follow
     the cor. conventions, are checked for availability and can be customised.
  6. Architecture preview, then Confirm: cor. deploys eventhub/azuredeploy-regions.json
     itself (ARM deployment with the admin's sign-in, no portal hand-off).
  7. Deployment: storage, containers, namespaces, then diagnostic settings for every
     selected resource (to the event hub of its region), Entra ID and the Activity log
     (to the primary region), then validation.
  8. Results: counts, connection strings with expiry and a connection test, failed and
     skipped resources with reasons. The admin's sign-in is discarded at the end.

PoC: records (including the connection strings) are kept in state/ (git-ignored).
"""

import collections
import concurrent.futures
import hashlib
import json
import os
import pathlib
import re
import secrets
import threading
import time
import urllib.parse

from . import auth, discovery, store
from . import eventhub as eh
from .web import Raw, Redirect

KIND = "azure-onboarding"
TARGET_NAME = os.environ.get("COR_TARGET_NAME", "cor.")
UI_FILE = pathlib.Path(__file__).resolve().parent / "onboard_ui.html"
TEMPLATE_FILE = eh.TEMPLATES / "azuredeploy-regions.json"
EH_API, ST_API, DIAG_API = eh.EH_API, eh.ST_API, discovery.API_DIAG
DIAG_NAME = eh.DIAG_NAME
POLICY = "corehSAS"
CONSUMER_GROUP = "$Default"
DEFAULT_RG = "cor-logging-rg"
DIAG_WORKERS = 8
ACTIVITY_CATEGORIES = ["Administrative", "Security", "ServiceHealth", "Alert", "Recommendation", "Policy",
                       "Autoscale", "ResourceHealth"]

# Resource categories, in the order of the Select Resources screen.
# mode: required (always on), auto (pre-selected). Anything else is "Other Resources".
CATEGORIES = [
    ("entra", "Microsoft Entra ID (Tenant)", "entra", set(), "required"),
    ("activity", "Subscription Activity Logs", "activity", set(), "required"),
    ("storage", "Storage Accounts", "storage", {"microsoft.storage/storageaccounts"}, "auto"),
    ("nsg", "Network Security Groups (NSGs)", "nsg", {"microsoft.network/networksecuritygroups"}, "auto"),
    ("appservice", "App Services", "web", {"microsoft.web/sites"}, "auto"),
    ("automation", "Automation Accounts", "automation", {"microsoft.automation/automationaccounts"}, "auto"),
    ("functions", "Function Apps", "functions", {"microsoft.web/sites"}, "auto"),
    ("keyvault", "Key Vaults", "keyvault", {"microsoft.keyvault/vaults"}, "auto"),
    ("sqlserver", "SQL Servers (Auditing)", "sql", {"microsoft.sql/servers"}, "auto"),
    ("sqldb", "SQL Databases", "sql", {"microsoft.sql/servers/databases"}, "auto"),
    ("firewall", "Azure Firewalls", "firewall", {"microsoft.network/azurefirewalls"}, "auto"),
    ("appgw", "Application Gateways", "gateway", {"microsoft.network/applicationgateways"}, "auto"),
    ("aks", "Kubernetes Services (AKS)", "aks", {"microsoft.containerservice/managedclusters"}, "auto"),
    ("logicapps", "Logic Apps", "logic", {"microsoft.logic/workflows"}, "auto"),
    ("cosmos", "Cosmos DB Accounts", "cosmos", {"microsoft.documentdb/databaseaccounts"}, "auto"),
]
TYPE_TO_CAT = {t: key for key, _l, _i, types, _m in CATEGORIES for t in types if t != "microsoft.web/sites"}
# Types listed but not onboarded through a diagnostic setting to an event hub.
TYPE_NOTES = {t: "Needs an agent (Azure Monitor Agent)" for t in discovery.AGENT_TYPES}
TYPE_NOTES[discovery.VNET_TYPE] = "Flow logs (Network Watcher → storage only)"
TYPE_LABELS = {
    "microsoft.compute/virtualmachines": "Virtual Machines",
    "microsoft.compute/virtualmachinescalesets": "VM Scale Sets",
    "microsoft.hybridcompute/machines": "Azure Arc Machines",
    "microsoft.network/virtualnetworks": "Virtual Networks",
    "microsoft.network/publicipaddresses": "Public IP Addresses",
    "microsoft.containerregistry/registries": "Container Registries",
    "microsoft.recoveryservices/vaults": "Recovery Services Vaults",
    "microsoft.servicebus/namespaces": "Service Bus Namespaces",
    "microsoft.eventhub/namespaces": "Event Hubs Namespaces",
    "microsoft.datafactory/factories": "Data Factories",
    "microsoft.apimanagement/service": "API Management",
    "microsoft.cdn/profiles": "Front Door / CDN Profiles",
    "microsoft.cognitiveservices/accounts": "AI Services",
    "microsoft.search/searchservices": "AI Search",
    "microsoft.dbforpostgresql/flexibleservers": "PostgreSQL Flexible Servers",
    "microsoft.dbformysql/flexibleservers": "MySQL Flexible Servers",
    "microsoft.cache/redis": "Azure Cache for Redis",
    "microsoft.network/virtualnetworkgateways": "VPN Gateways",
    "microsoft.network/bastionhosts": "Bastion Hosts",
    "microsoft.network/frontdoors": "Front Doors (classic)",
    "microsoft.synapse/workspaces": "Synapse Workspaces",
    "microsoft.batch/batchaccounts": "Batch Accounts",
    "microsoft.signalrservice/signalr": "SignalR Services",
    "microsoft.machinelearningservices/workspaces": "Machine Learning Workspaces",
}

PENDING = {}    # sign-in state -> request (one-time)
SESSIONS = {}   # onboarding id -> the admin's access token, memory only
DISC = {}       # onboarding id -> discovery (memory only: rebuilt by a new scan)
RECS = {}       # onboarding id -> record (written to state/ at each milestone)
_lock = threading.RLock()


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _json(obj, status=200):
    return Raw(json.dumps(obj), "application/json; charset=utf-8", status=status)


# --- Records ---------------------------------------------------------------------------------

def _valid_id(cid):
    return bool(re.fullmatch(r"[0-9a-f]{16}", cid or ""))


def _rec(cid):
    if not _valid_id(cid):
        return None
    with _lock:
        if cid not in RECS:
            rec = store.load(KIND, cid)
            if rec is None:
                return None
            RECS[cid] = rec
        return RECS[cid]


def _save(cid):
    with _lock:
        rec = RECS.get(cid)
        if rec is not None:
            rec["updatedAt"] = _now()
            store.save(KIND, cid, rec)


def _log(cid, kind, text):
    with _lock:
        rec = RECS.get(cid)
        if rec is not None:
            rec.setdefault("log", []).append([kind, text, _now()[11:]])


class _Stop(Exception):
    """Work on this onboarding cannot go on (cancelled, deleted, sign-in gone)."""


def _tok(cid):
    rec = RECS.get(cid)
    if rec is None:
        raise _Stop("This onboarding was deleted.")
    if rec.get("cancelled"):
        raise _Stop("Cancelled by the admin.")
    sess = SESSIONS.get(cid)
    if not sess:
        raise _Stop("The Azure sign-in is no longer held: sign in again.")
    if time.time() > sess["until"]:
        _drop(cid, "sign-in expired")
        raise _Stop("The Azure sign-in expired: sign in again.")
    return sess["access"]


def _drop(cid, reason):
    """Discard the admin's access token: the only copy is this in-memory entry."""
    sess = SESSIONS.pop(cid, None)
    if sess is None:
        return
    sess.clear()
    with _lock:
        rec = RECS.get(cid)
        if rec is not None:
            rec["signInDiscardedAt"], rec["signInDiscardedReason"] = _now(), reason
    _log(cid, "ok", f"Discarded the admin's Azure sign-in ({reason}). No refresh token was issued: cor. cannot "
                    "act as the admin again without a new sign-in.")
    _save(cid)


def _live(cid):
    sess = SESSIONS.get(cid)
    return bool(sess) and time.time() < sess["until"]


# --- Sign in -------------------------------------------------------------------------------

def start(form):
    app = eh.onboarding_app()
    if not app:
        return Redirect("/?msg=" + urllib.parse.quote("The cor. onboarding app is not registered on this Hub."))
    cid = secrets.token_hex(8)
    tenant = (form.get("tenant") or "").strip() or "organizations"
    with _lock:
        RECS[cid] = {"id": cid, "createdAt": _now(), "updatedAt": _now(), "phase": "signin", "log": []}
    _save(cid)
    verifier, challenge = auth.pkce()
    state = secrets.token_urlsafe(16)
    PENDING[state] = {"id": cid, "tenant": tenant, "verifier": verifier}
    return Redirect(auth.authorize_url(tenant, app["appId"], eh.REDIRECT_URI, eh.SCOPES, state, challenge,
                                       prompt=eh._prompt(form.get("consent") == "1")))


def callback(q):
    """The onboarding app has one redirect URI: sign-ins started here are handled here, the
    single-hub (/eh) flow's go to eventhub.callback."""
    req = PENDING.pop(q.get("state", ""), None)
    if req is None:
        return eh.callback(q)
    cid = req["id"]
    rec = _rec(cid)
    if rec is None:
        return Redirect("/?msg=" + urllib.parse.quote("That onboarding was deleted: start a new one."))
    if q.get("error"):
        rec.update(phase="failed", error=f"Microsoft sign-in was not completed: {q.get('error_description') or q['error']}")
        _save(cid)
        return Redirect(f"/?id={cid}")
    app = eh.onboarding_app()
    try:
        tok = auth.redeem_code(req["tenant"], app["appId"], q["code"], eh.REDIRECT_URI, req["verifier"], eh.SCOPES)
    except auth.HttpError as exc:
        rec.update(phase="failed", error=f"Sign-in failed — {exc}")
        _save(cid)
        return Redirect(f"/?id={cid}")
    c = auth.claims(tok["access_token"])
    who = c.get("upn") or c.get("unique_name") or c.get("preferred_username") or "the admin"
    SESSIONS[cid] = {"access": tok["access_token"],
                     "until": time.time() + int(tok.get("expires_in", 3600)) - 120}
    minutes = int((SESSIONS[cid]["until"] - time.time()) // 60)
    tok.clear()
    rec.update(phase="scanning", tenant=c.get("tid"), signedInAs=who)
    _log(cid, "ok", f"Signed in as {who}: Azure Resource Manager access for this onboarding (one access token, "
                    f"memory only, usable for {minutes} minutes, no refresh token).")
    _save(cid)
    threading.Thread(target=_scan, args=(cid,), daemon=True, name=f"scan-{cid}").start()
    return Redirect(f"/?id={cid}")


# --- 2. Scan --------------------------------------------------------------------------------

SCAN_STEPS = [("connect", "Connecting to Azure"), ("subs", "Reading subscriptions"),
              ("regions", "Discovering regions"), ("resources", "Scanning resources"),
              ("categorize", "Categorizing resources"), ("prepare", "Preparing selection")]


def _category_of(r):
    if r["type"] == "microsoft.web/sites":
        return "functions" if "functionapp" in (r.get("kind") or "") else "appservice"
    return TYPE_TO_CAT.get(r["type"])


def _type_label(rtype):
    if rtype in TYPE_LABELS:
        return TYPE_LABELS[rtype]
    provider, _, rest = rtype.partition("/")
    return f"{provider.split('.')[-1].title()} · {rest}"


def _scan(cid):
    rec = RECS[cid]
    scan = {"pct": 0, "steps": [{"key": k, "label": l, "state": "pending", "detail": ""} for k, l in SCAN_STEPS]}
    with _lock:
        rec["scan"] = scan

    def mark(key, state=None, pct=None, detail=None):
        with _lock:
            step = next(s for s in scan["steps"] if s["key"] == key)
            if state:
                step["state"] = state
            if detail is not None:
                step["detail"] = detail
            if pct is not None:
                scan["pct"] = max(scan["pct"], int(pct))

    current = "connect"
    try:
        mark("connect", "running", 2)
        tok = _tok(cid)
        subs = discovery.subscriptions(tok)
        mark("connect", "done", 6)
        current = "subs"
        mark("subs", "running")
        if not subs:
            raise _Stop("This account can see no enabled Azure subscription.")
        mark("subs", "done", 10, f"{len(subs)} found")
        current = "regions"
        mark("regions", "running")
        locs = discovery.locations(tok, subs[0]["subscriptionId"])
        mark("regions", "done", 14)
        current = "resources"
        mark("resources", "running", 15, "0 found")
        sub_ids = [s["subscriptionId"] for s in subs]

        def found(n, total):
            _tok(cid)  # stop early when cancelled
            mark("resources", pct=15 + 25 * min(1, n / total) if total else None, detail=f"{n:,} found")

        resources = discovery.list_resources(tok, sub_ids, found)
        excluded = [r for r in resources if r["type"] in discovery.EXCLUDE_TYPES
                    or (r["type"] == "microsoft.sql/servers/databases" and r["name"].lower() == "master")]
        kept = [r for r in resources if r not in excluded] if excluded else resources
        mark("resources", "done", 40, f"{len(kept):,} found" + (f", {len(excluded):,} excluded (no useful logs)"
                                                              if excluded else ""))
        current = "categorize"
        mark("categorize", "running", 41, "checking existing log settings")
        probe = [r for r in kept if r["type"] not in discovery.AGENT_TYPES]
        flowlog = discovery.flow_logs(tok, sub_ids) if any(r["type"] == discovery.VNET_TYPE for r in probe) else {}

        def probed(n, total):
            _tok(cid)
            mark("categorize", pct=41 + 47 * n / max(total, 1), detail=f"checking existing log settings {n:,}/{total:,}")

        states = discovery.probe_all(tok, probe, flowlog, probed)
        state_by_id = {r["id"]: s for r, s in zip(probe, states)}
        activity = {s: discovery.probe_activity(tok, s) for s in sub_ids}
        entra = discovery.probe_entra(tok)
        mark("categorize", "done", 90, f"{len(probe):,} resources checked")
        current = "prepare"
        mark("prepare", "running", 92)
        _build(cid, subs, locs, kept, state_by_id, activity, entra)
        mark("prepare", "done", 100)
        with _lock:
            rec["phase"] = "select"
        _log(cid, "ok", f"Scanned {len(subs)} subscription(s): {len(kept):,} resources in "
                        f"{rec['summary']['regions']} region(s).")
        _save(cid)
    except _Stop as exc:
        _scan_failed(cid, current, mark, str(exc))
    except (auth.HttpError, OSError) as exc:
        _scan_failed(cid, current, mark, f"Azure answered: {exc}")
    except Exception as exc:  # noqa: BLE001  (shown on the page, never a secret)
        _scan_failed(cid, current, mark, f"{type(exc).__name__}: {exc}")


def _scan_failed(cid, step, mark, text):
    if cid not in RECS:
        return
    mark(step, "failed", detail=text)
    with _lock:
        rec = RECS[cid]
        if not rec.get("cancelled"):
            rec.update(phase="failed", error=text, failedAt="scan")
    _log(cid, "fail", f"Scan stopped: {text}")
    _drop(cid, "scan stopped")
    _save(cid)


def _compact_state(s):
    if not s:
        return ["-", ""]
    code = {"Enabled": "E", "Disabled": "D", "Not accessible": "N"}.get(s.get("status"), "U")
    return [code, ", ".join(s.get("destNames") or s.get("destTypes") or [])[:80]]


def _build(cid, subs, locs, resources, state_by_id, activity, entra):
    sub_index = {s["subscriptionId"]: i for i, s in enumerate(subs)}
    loc_names, loc_index = [], {}
    types, type_index = [], {}
    res, ids, kinds = [], [], []
    for r in sorted(resources, key=lambda x: (x["type"], (x.get("name") or "").lower())):
        loc = r.get("location") or "global"
        if loc not in loc_index:
            loc_index[loc] = len(loc_names)
            loc_names.append(loc)
        cat = _category_of(r)
        tkey = (r["type"], cat)
        if tkey not in type_index:
            type_index[tkey] = len(types)
            note = TYPE_NOTES.get(r["type"], "")
            types.append({"type": r["type"], "cat": cat or "other", "sel": cat or f"t{len(types)}", "note": note,
                          "label": next(c[1] for c in CATEGORIES if c[0] == cat) if cat else _type_label(r["type"]),
                          "count": 0})
        t = types[type_index[tkey]]
        t["count"] += 1
        res.append([r.get("name") or "", r.get("resourceGroup") or "", type_index[tkey], loc_index[loc],
                    sub_index.get(r["subscriptionId"], 0), *_compact_state(state_by_id.get(r["id"]))])
        ids.append(r["id"])
        kinds.append(r)
    regional = [l for l in loc_names if l != "global"]
    per_sub = collections.defaultdict(collections.Counter)
    for row in res:
        per_sub[row[4]][loc_names[row[3]]] += 1
    subs_out = [{"id": s["subscriptionId"], "name": s.get("displayName") or s["subscriptionId"],
                 "count": sum(per_sub[i].values()),
                 "regions": [l for l, _ in per_sub[i].most_common() if l != "global"],
                 "activity": _compact_state(activity.get(s["subscriptionId"]))} for i, s in enumerate(subs)]
    cats = [{"key": k, "label": l, "icon": i, "mode": m,
             "count": sum(t["count"] for t in types if t["cat"] == k)} for k, l, i, _t, m in CATEGORIES]
    disc = {"subs": subs_out, "locs": [{"name": l, "display": locs.get(l, "Global" if l == "global" else l)}
                                       for l in loc_names],
            "types": types, "cats": cats, "res": res, "entra": _compact_state(entra), "target": TARGET_NAME}
    with _lock:
        DISC[cid] = {"client": disc, "ids": ids, "raw": kinds, "avail": {}}
        RECS[cid]["summary"] = {"subscriptions": len(subs), "regions": len(regional), "resources": len(res),
                                "types": len({t["type"] for t in types})}


# --- 3-5. Selection and plan -------------------------------------------------------------------

def _selected(cid, sel):
    d = DISC[cid]
    client = d["client"]
    subs = set(sel.get("subs", range(len(client["subs"]))))
    cats, inc, exc = set(sel.get("cats", [])), set(sel.get("inc", [])), set(sel.get("exc", []))
    out = []
    for i, row in enumerate(client["res"]):
        t = client["types"][row[2]]
        if t["note"] or row[4] not in subs:
            continue
        if i in inc or (t["sel"] in cats and i not in exc):
            out.append(i)
    return out, sorted(subs)


def _suffix(cid, sub):
    tenant = RECS[cid].get("tenant") or ""
    return hashlib.sha1(f"{tenant}/{sub}".encode()).hexdigest()[:6]


NAME_RULES = {
    "namespace": (r"[A-Za-z][A-Za-z0-9-]{4,48}[A-Za-z0-9]", "6-50 letters, numbers and hyphens, starting with a "
                                                             "letter and ending with a letter or number"),
    "eventHub": (r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}", "1-256 letters, numbers, periods, hyphens, underscores"),
    "storage": (r"[a-z0-9]{3,24}", "3-24 lowercase letters and numbers"),
    "container": (r"[a-z0-9](?!.*--)[a-z0-9-]{1,61}[a-z0-9]", "3-63 lowercase letters, numbers and single hyphens"),
    "resourceGroup": (r"[-\w.()]{0,89}[-\w()]", "1-90 letters, numbers, ., _, -, ( ), not ending with a period"),
}


def _name_error(kind, name):
    pattern, text = NAME_RULES[kind]
    return None if re.fullmatch(pattern, name or "") else text


def _availability(cid, tok, kind, sub, rg, name):
    """new: free to create; exists: already ours in the target resource group (reused);
    taken: used elsewhere; unknown: could not check (the deployment validation will)."""
    cache = DISC[cid]["avail"]
    key = (kind, sub, rg.lower(), name.lower())
    if key in cache:
        return cache[key]
    provider, rtype, body, api = (
        ("Microsoft.EventHub", "namespaces", {"name": name}, EH_API) if kind == "namespace" else
        ("Microsoft.Storage", "storageAccounts", {"name": name, "type": "Microsoft.Storage/storageAccounts"}, ST_API))
    try:
        resp = eh.arm("POST", f"/subscriptions/{sub}/providers/{provider}/checkNameAvailability", tok,
                      body=body, api=api, attempts=2) or {}
        if resp.get("nameAvailable"):
            result = "new"
        else:
            try:
                eh.arm("GET", f"/subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{rtype}/{name}", tok,
                       api=api, attempts=2)
                result = "exists"
            except auth.HttpError:
                result = "taken"
    except (auth.HttpError, OSError):
        result = "unknown"
    cache[key] = result
    return result


def _plan(cid, sel, target, names):
    d = DISC[cid]
    client = d["client"]
    chosen, subs = _selected(cid, sel)
    loc_of = [l["name"] for l in client["locs"]]
    counts = collections.Counter(loc_of[client["res"][i][3]] for i in chosen)
    global_count = counts.pop("global", 0)
    regions = [r for r, _ in counts.most_common()]
    all_regional = [l for l in loc_of if l != "global"]
    primary = (target.get("primary") if target.get("primary") in regions else None) or \
              (regions[0] if regions else target.get("primary") or (all_regional[0] if all_regional else "eastus"))
    if primary not in regions:
        regions.insert(0, primary)
    display = {l["name"]: l["display"] for l in client["locs"]}
    sub = target.get("subscription") or (client["subs"][subs[0]]["id"] if subs else client["subs"][0]["id"])
    rg = (target.get("resourceGroup") or DEFAULT_RG).strip()
    sfx = _suffix(cid, sub)
    tok = _tok(cid)
    errors = []
    if _name_error("resourceGroup", rg):
        errors.append(f"Resource group: {_name_error('resourceGroup', rg)}.")

    rows = []
    for reg in regions:
        row = {"region": reg, "display": display.get(reg, reg), "count": counts.get(reg, 0),
               "global": global_count if reg == primary else 0, "primary": reg == primary}
        for kind, field, default in (("namespace", "namespace", f"corehns-{reg}"),
                                     ("eventHub", "eventHub", f"coreh-{reg}"),
                                     ("container", "container", f"corcontainer-{reg}")):
            custom = (names.get(f"{field}:{reg}") or "").strip()
            row[field] = custom or default
            row[field + "Custom"] = bool(custom)
            err = _name_error(kind, row[field])
            if err:
                errors.append(f"{row['display']} {field}: {err}.")
        rows.append(row)

    st_custom = (names.get("storage") or "").strip().lower()
    storage = {"name": st_custom or "corstorage", "custom": bool(st_custom),
               "location": target.get("storageLocation") if target.get("storageLocation") in all_regional + regions
               else primary}
    storage["display"] = display.get(storage["location"], storage["location"])
    if _name_error("storage", storage["name"]):
        errors.append(f"Storage account: {_name_error('storage', storage['name'])}.")

    # Global uniqueness: namespaces and the storage account are public DNS names.
    def check(kind, item, field, fallback):
        if _name_error("namespace" if kind == "namespace" else "storage", item[field]):
            return
        status = _availability(cid, tok, kind, sub, rg, item[field])
        if status == "taken" and not item.get(field + "Custom", item.get("custom")):
            original = item[field]
            item[field] = fallback
            status = _availability(cid, tok, kind, sub, rg, fallback)
            item["note"] = f"{original} is taken in Azure: using {fallback}."
        item["status"] = status
        if status == "taken":
            errors.append(f"{item[field]} is already used in Azure: choose another name.")

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        jobs = [pool.submit(check, "namespace", r, "namespace", f"{r['namespace'][:43]}-{sfx}") for r in rows]
        jobs.append(pool.submit(check, "storage", storage, "name", f"corstorage{sfx}"))
        for j in jobs:
            j.result()
    for r in rows:
        r["nsStatus"] = r.pop("status", "unknown")
        r["nsNote"] = r.pop("note", "")
    if len({r["namespace"].lower() for r in rows}) < len(rows):
        errors.append("Two regions have the same namespace name.")
    if len({r["container"] for r in rows}) < len(rows):
        errors.append("Two regions have the same container name.")

    by_cat = collections.Counter(client["types"][client["res"][i][2]]["cat"] for i in chosen)
    sub_names = {s["id"]: s["name"] for s in client["subs"]}
    return {"regions": rows, "storage": storage, "primary": primary, "primaryDisplay": display.get(primary, primary),
            "target": {"subscription": sub, "subscriptionName": sub_names.get(sub, sub), "resourceGroup": rg},
            "selected": len(chosen), "global": global_count, "byCategory": dict(by_cat),
            "activitySubscriptions": len(subs), "entra": True, "errors": errors,
            "categories": sorted({client["types"][client["res"][i][2]]["label"] for i in chosen})}


def _form_data(form):
    try:
        return json.loads(form.get("data") or "{}")
    except ValueError:
        return {}


def api_plan(form):
    cid = form.get("id", "")
    rec = _rec(cid)
    if rec is None or cid not in DISC:
        return _json({"error": "This onboarding has no scan in memory: sign in again."}, 409)
    data = _form_data(form)
    try:
        return _json(_plan(cid, data.get("selection") or {}, data.get("target") or {}, data.get("names") or {}))
    except _Stop as exc:
        return _json({"error": str(exc)}, 409)


# --- 6-7. Deploy ------------------------------------------------------------------------------

DEPLOY_STEPS = [("validate", "Validating configuration", 5), ("storage", "Deploying Storage Account", 10),
                ("containers", "Creating containers", 5), ("namespaces", "Deploying Event Hub namespaces", 25),
                ("diagnostics", "Configuring diagnostic settings", 45), ("verify", "Validating deployment", 10)]


class _DeployFailed(Exception):
    pass


def api_deploy(form):
    cid = form.get("id", "")
    rec = _rec(cid)
    if rec is None or cid not in DISC:
        return _json({"error": "This onboarding has no scan in memory: sign in again."}, 409)
    if rec.get("phase") == "deploying":
        return _json({"ok": True})
    if rec.get("phase") != "select":
        return _json({"error": "This onboarding can no longer deploy: start a new one."}, 409)
    data = _form_data(form)
    try:
        plan = _plan(cid, data.get("selection") or {}, data.get("target") or {}, data.get("names") or {})
    except _Stop as exc:
        return _json({"error": str(exc)}, 409)
    if plan["errors"]:
        return _json({"error": " ".join(plan["errors"]), "plan": plan}, 400)
    chosen, subs = _selected(cid, data.get("selection") or {})
    n = len(plan["regions"])
    labels = {"storage": f"Deploying Storage Account ({plan['storage']['name']})",
              "containers": f"Creating containers ({n})", "namespaces": f"Deploying Event Hub namespaces ({n})",
              "diagnostics": f"Configuring diagnostic settings ({len(chosen):,} resources)"}
    with _lock:
        rec.update(phase="deploying", plan=plan, selection=data.get("selection") or {}, error=None,
                   deploy={"pct": 0, "steps": [{"key": k, "label": labels.get(k, l), "state": "pending", "detail": ""}
                                               for k, l, _w in DEPLOY_STEPS]})
        rec.pop("results", None)
    _log(cid, "info", f"Deployment confirmed: {n} region(s), {len(chosen):,} resources.")
    _save(cid)
    threading.Thread(target=_deploy, args=(cid, plan, chosen, subs), daemon=True, name=f"deploy-{cid}").start()
    return _json({"ok": True})


def _deploy(cid, plan, chosen, subs):
    rec = RECS[cid]
    dep = rec["deploy"]
    weights = {k: w for k, _l, w in DEPLOY_STEPS}

    def mark(key, state=None, detail=None, frac=None):
        with _lock:
            step = next(s for s in dep["steps"] if s["key"] == key)
            if state:
                step["state"] = state
            if detail is not None:
                step["detail"] = detail
            if frac is not None:
                step["frac"] = frac
            total = 0
            for s in dep["steps"]:
                f = 1 if s["state"] == "done" else s.get("frac", 0) if s["state"] == "running" else 0
                total += weights[s["key"]] * f
            dep["pct"] = int(total)

    current = "validate"
    sub, rg = plan["target"]["subscription"], plan["target"]["resourceGroup"]
    rg_path = f"/subscriptions/{sub}/resourceGroups/{rg}"
    try:
        mark("validate", "running", "creating the resource group and validating the template")
        tok = _tok(cid)
        eh.arm("PUT", rg_path, tok, api="2021-04-01", body={
            "location": plan["primary"], "tags": {"cor-integration": "eventhub", "cor-connection-id": cid}})
        name = f"cor-logging-{cid}"
        body = {"properties": {"mode": "Incremental", "template": json.loads(TEMPLATE_FILE.read_text(encoding="utf-8")),
                               "parameters": {k: {"value": v} for k, v in {
                                   "regions": [{"location": r["region"], "namespaceName": r["namespace"],
                                                "eventHubName": r["eventHub"], "containerName": r["container"]}
                                               for r in plan["regions"]],
                                   "storageAccountName": plan["storage"]["name"],
                                   "storageLocation": plan["storage"]["location"],
                                   "sharedAccessPolicyName": POLICY, "corConnectionId": cid}.items()}}}
        dep_path = f"{rg_path}/providers/Microsoft.Resources/deployments/{name}"
        try:
            eh.arm("POST", f"{dep_path}/validate", tok, api="2022-09-01", body=body)
        except auth.HttpError as exc:
            raise _DeployFailed(f"Template validation failed — {_arm_error(exc.body)}")
        mark("validate", "done", f"resource group {rg} in {plan['primaryDisplay']}")

        # Deploy and follow the operations of the deployment.
        current = "storage"
        eh.arm("PUT", dep_path, tok, api="2022-09-01", body=body)
        n = len(plan["regions"])
        while True:
            time.sleep(POLL_SECONDS)
            tok = _tok(cid)
            state = ((eh.arm("GET", dep_path, tok, api="2022-09-01") or {}).get("properties") or {})
            ops = eh.arm_list(f"{dep_path}/operations", tok, api="2022-09-01")
            ok = collections.Counter()
            started = collections.Counter()
            for op in ops:
                p = op.get("properties") or {}
                rtype = ((p.get("targetResource") or {}).get("resourceType") or "").lower()
                started[rtype] += 1
                if p.get("provisioningState") == "Succeeded":
                    ok[rtype] += 1
            st_t, ct_t = "microsoft.storage/storageaccounts", "microsoft.storage/storageaccounts/blobservices/containers"
            ns_types = ("microsoft.eventhub/namespaces", "microsoft.eventhub/namespaces/eventhubs",
                        "microsoft.eventhub/namespaces/authorizationrules")
            ns_ok = sum(ok[t] for t in ns_types)
            for key, done_n, total_n, any_started, unit in (
                    ("storage", ok[st_t], 1, started[st_t], "account"),
                    ("containers", ok[ct_t], n, started[ct_t], "containers"),
                    ("namespaces", ns_ok, 3 * n, sum(started[t] for t in ns_types), "resources")):
                if done_n >= total_n:
                    mark(key, "done", "")
                elif any_started:
                    mark(key, "running", f"{done_n}/{total_n} {unit}" if total_n > 1 else "", frac=done_n / total_n)
            if state.get("provisioningState") == "Succeeded":
                for key in ("storage", "containers", "namespaces"):
                    mark(key, "done", "")
                break
            if state.get("provisioningState") in ("Failed", "Canceled"):
                with _lock:  # show the failure on the first step that did not finish
                    current = next((s["key"] for s in dep["steps"]
                                    if s["key"] in ("storage", "containers", "namespaces") and s["state"] != "done"),
                                   "namespaces")
                raise _DeployFailed(_deployment_error(state, ops))
        _log(cid, "ok", f"ARM deployment {name} succeeded: storage {plan['storage']['name']}, {n} namespace(s).")

        # Connection strings.
        current = "diagnostics"
        mark("diagnostics", "running", "retrieving connection strings")
        creds = _credentials(tok, plan)
        with _lock:
            rec["credentials"] = creds
        _log(cid, "ok", f"Retrieved {n} Event Hub connection string(s) and the storage connection string.")
        _save(cid)

        # Diagnostic settings.
        results = _configure_all(cid, plan, chosen, subs, creds,
                                 lambda done, total: mark("diagnostics", detail=f"{done:,}/{total:,}",
                                                          frac=done / max(total, 1)))
        mark("diagnostics", "done", f"{results['onboarded']:,} onboarded, {results['failedSkipped']:,} failed/skipped")

        # Validation: the connector's view (connection strings only).
        current = "verify"
        mark("verify", "running", "testing the connection strings")
        _drop(cid, "deployment finished")  # the tests need no Azure access
        tests = _run_tests(creds)
        mark("verify", "done" if tests["ok"] else "failed",
             "all connections work" if tests["ok"] else "a connection test failed")
        with _lock:
            rec.update(phase="done", results=results, tests=tests, finishedAt=_now())
            dep["pct"] = 100
        _log(cid, "ok" if tests["ok"] else "warn", "Onboarding finished.")
        _save(cid)
    except (_Stop, _DeployFailed, auth.HttpError, OSError, Exception) as exc:  # noqa: BLE001
        text = str(exc) if isinstance(exc, (_Stop, _DeployFailed)) else \
            f"Azure answered: {exc}" if isinstance(exc, (auth.HttpError, OSError)) else f"{type(exc).__name__}: {exc}"
        if cid not in RECS:
            return
        mark(current, "failed", text)
        with _lock:
            if not rec.get("cancelled"):
                rec.update(phase="failed", error=text, failedAt="deploy")
        _log(cid, "fail", f"Deployment stopped: {text}")
        _drop(cid, "deployment stopped")
        _save(cid)


POLL_SECONDS = 5


def _arm_error(body):
    err = (body or {}).get("error") if isinstance(body, dict) else None
    if not isinstance(err, dict):
        return auth.error_text(body)
    parts = [f"{err.get('code')}: {err.get('message')}"]
    for d in err.get("details") or []:
        parts.append(f"{d.get('code')}: {d.get('message')}")
    return " | ".join(parts)[:900]


def _deployment_error(state, ops):
    msgs = []
    for op in ops:
        p = op.get("properties") or {}
        if p.get("provisioningState") == "Failed":
            target = (p.get("targetResource") or {}).get("resourceName") or ""
            err = ((p.get("statusMessage") or {}).get("error") or {})
            msgs.append(f"{target}: {err.get('code')}: {err.get('message')}")
    if not msgs and state.get("error"):
        msgs.append(_arm_error({"error": state["error"]}))
    return "The ARM deployment failed — " + (" | ".join(msgs)[:900] or "no details from Azure")


def _credentials(tok, plan):
    sub, rg = plan["target"]["subscription"], plan["target"]["resourceGroup"]
    base = f"/subscriptions/{sub}/resourceGroups/{rg}/providers"
    regions = []
    for r in plan["regions"]:
        rule = f"{base}/Microsoft.EventHub/namespaces/{r['namespace']}/authorizationRules/{POLICY}"
        keys = eh.arm("POST", f"{rule}/listKeys", tok, api=EH_API)
        regions.append({"region": r["region"], "display": r["display"], "namespace": r["namespace"],
                        "eventHub": r["eventHub"], "container": r["container"], "consumerGroup": CONSUMER_GROUP,
                        "policy": POLICY, "ruleId": rule, "connectionString": keys["primaryConnectionString"]})
    st = plan["storage"]["name"]
    st_id = f"{base}/Microsoft.Storage/storageAccounts/{st}"
    key1 = eh.arm("POST", f"{st_id}/listKeys", tok, api=ST_API)["keys"][0]
    props = (eh.arm("GET", st_id, tok, api=ST_API) or {}).get("properties") or {}
    return {"regions": regions, "storage": {
        "name": st, "location": plan["storage"]["location"], "display": plan["storage"]["display"],
        "connectionString": f"DefaultEndpointsProtocol=https;AccountName={st};AccountKey={key1['value']};"
                            "EndpointSuffix=core.windows.net",
        "expiry": eh._expiry(key1, props)}}


# --- Diagnostic settings -------------------------------------------------------------------

def _logs_for(tok, target_id, cache, cache_key):
    """The log part of a diagnostic setting for this resource: allLogs when the resource
    offers category groups, else every log category. None when it has no logs."""
    if cache_key not in cache:
        cats = eh.arm_list(f"{target_id}/providers/microsoft.insights/diagnosticSettingsCategories", tok, api=DIAG_API)
        logs = [c for c in cats if (c.get("properties") or {}).get("categoryType") == "Logs"]
        if not logs:
            cache[cache_key] = None
        elif any("allLogs" in ((c.get("properties") or {}).get("categoryGroups") or []) for c in logs):
            cache[cache_key] = [{"categoryGroup": "allLogs", "enabled": True}]
        else:
            cache[cache_key] = [{"category": c["name"], "enabled": True} for c in logs]
    return cache[cache_key]


def _configure_target(tok, target_id, cache_key, rule_id, hub, cache):
    """(status, reason) for one resource or storage service."""
    current = discovery.probe_diag(tok, target_id)
    if current["status"] == "Not accessible":
        return "failed", "No access to its diagnostic settings (needs Monitoring Contributor)."
    for h in current.get("eventHubs", []):
        if h["rule"] == rule_id.lower() and h["hub"] == hub.lower():
            return "already", f"Already streams to {hub} (setting '{h['setting']}')."
    others = [n for n in current.get("settings", []) if n != DIAG_NAME]
    if len(others) >= 5:
        return "skipped", "Already has 5 diagnostic settings (the Azure limit)."
    try:
        logs = _logs_for(tok, target_id, cache, cache_key)
    except auth.HttpError as exc:
        return "skipped", f"Diagnostic settings are not supported here ({exc.status})."
    if not logs:
        return "skipped", "No log categories (metrics only)."
    eh.arm("PUT", f"{target_id}/providers/microsoft.insights/diagnosticSettings/{DIAG_NAME}", tok, api=DIAG_API,
           body={"properties": {"eventHubAuthorizationRuleId": rule_id, "eventHubName": hub, "logs": logs}})
    return "onboarded", ""


def _configure_sql_server(tok, server_id, rule_id, hub):
    """Server auditing to the event hub: the master database's SQLSecurityAuditEvents
    diagnostic setting plus auditing with the Azure Monitor target."""
    audit = (eh.arm("GET", f"{server_id}/auditingSettings/default", tok, api=discovery.API_SQL_AUDIT) or {})
    props = audit.get("properties") or {}
    if (props.get("state") or "").lower() == "enabled" and props.get("storageEndpoint"):
        if props.get("isAzureMonitorTargetEnabled"):
            pass  # only the diagnostic setting is missing
        else:
            return "skipped", ("Auditing already writes to a storage account: add the Azure Monitor target in the "
                               "portal to keep it (cor. does not overwrite it).")
    status, reason = _configure_target(tok, f"{server_id}/databases/master", "sql-master", rule_id, hub,
                                       {"sql-master": [{"category": "SQLSecurityAuditEvents", "enabled": True}]})
    if status in ("failed", "skipped"):
        return status, reason
    if not ((props.get("state") or "").lower() == "enabled" and props.get("isAzureMonitorTargetEnabled")):
        eh.arm("PUT", f"{server_id}/auditingSettings/default", tok, api=discovery.API_SQL_AUDIT,
               body={"properties": {"state": "Enabled", "isAzureMonitorTargetEnabled": True,
                                    "auditActionsAndGroups": props.get("auditActionsAndGroups") or [
                                        "SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP",
                                        "FAILED_DATABASE_AUTHENTICATION_GROUP", "BATCH_COMPLETED_GROUP"]}})
    return status, reason


def _configure_resource(tok, raw, rule_id, hub, cache):
    rtype = raw["type"]
    if rtype == discovery.SQL_SERVER_TYPE:
        return _configure_sql_server(tok, raw["id"], rule_id, hub)
    if rtype == discovery.STORAGE_TYPE:
        outcomes = []
        for path, label in discovery.STORAGE_SERVICES:
            s, why = _configure_target(tok, f"{raw['id']}/{path}/default", f"{rtype}/{path}", rule_id, hub, cache)
            outcomes.append((label, s, why))
        states = {s for _l, s, _w in outcomes}
        bad = [f"{l}: {w}" for l, s, w in outcomes if s in ("failed", "skipped")]
        if "failed" in states:
            return "failed", " ".join(bad)
        if "onboarded" in states:
            return "onboarded", ""
        if states == {"already"}:
            return "already", "All four services already stream to the hub."
        return ("already" if "already" in states else "skipped"), " ".join(bad)
    return _configure_target(tok, raw["id"], rtype, rule_id, hub, cache)


def _configure_all(cid, plan, chosen, subs, creds, progress):
    d = DISC[cid]
    client = d["client"]
    by_region = {r["region"]: r for r in creds["regions"]}
    primary = by_region[plan["primary"]]
    loc_of = [l["name"] for l in client["locs"]]
    cache, lock = {}, threading.Lock()
    counts = collections.defaultdict(collections.Counter)
    issues, done = [], [0]
    total = len(chosen) + len(subs) + 1

    def record(cat, label, name, region, status, reason):
        with lock:
            counts[cat][status] += 1
            if status != "onboarded":
                issues.append({"name": name, "type": label, "region": region, "status": status, "reason": reason})
            done[0] += 1
            if done[0] % 10 == 0 or done[0] == total:
                progress(done[0], total)

    def one(i):
        row = client["res"][i]
        t = client["types"][row[2]]
        loc = loc_of[row[3]]
        target = by_region.get(loc, primary)
        try:
            status, reason = _configure_resource(_tok(cid), d["raw"][i], target["ruleId"], target["eventHub"], cache)
        except _Stop:
            raise
        except auth.HttpError as exc:
            status = "failed"
            reason = ("No permission to change its diagnostic settings (needs Monitoring Contributor)."
                      if exc.status == 403 else _arm_error(exc.body)[:300])
        except Exception as exc:  # noqa: BLE001
            status, reason = "failed", f"{type(exc).__name__}: {exc}"[:300]
        record(t["cat"], t["label"], row[0], target["display"] if loc != "global" else "Global → " + primary["display"],
               status, reason)

    # Tenant and subscriptions first (primary region).
    entra = _entra(_tok(cid), primary["ruleId"], primary["eventHub"])
    record("entra", "Microsoft Entra ID", "Tenant", primary["display"],
           {"on": "onboarded", "partial": "onboarded", "already": "already"}.get(entra["status"], "failed"),
           entra.get("reason", ""))
    activity = []
    for si in subs:
        s = client["subs"][si]
        status, reason = _activity(_tok(cid), s["id"], primary["ruleId"], primary["eventHub"])
        activity.append({"subscription": s["name"], "status": status, "reason": reason})
        record("activity", "Activity Log", s["name"], primary["display"], status, reason)

    with concurrent.futures.ThreadPoolExecutor(max_workers=DIAG_WORKERS) as pool:
        for f in [pool.submit(one, i) for i in chosen]:
            f.result()

    onboarded = sum(c["onboarded"] + c["already"] for c in counts.values())
    failed_skipped = sum(c["failed"] + c["skipped"] for c in counts.values())
    order = {"failed": 0, "skipped": 1, "already": 2}
    issues.sort(key=lambda x: (order.get(x["status"], 3), x["type"], x["name"]))
    return {"selected": len(chosen), "tenantAndSubscriptions": len(subs) + 1,
            "onboarded": onboarded, "already": sum(c["already"] for c in counts.values()),
            "failedSkipped": failed_skipped, "failed": sum(c["failed"] for c in counts.values()),
            "skipped": sum(c["skipped"] for c in counts.values()),
            "byCategory": {k: dict(v) for k, v in counts.items()}, "issues": issues[:3000],
            "entra": entra, "activity": activity}


def _entra(tok, rule_id, hub):
    try:
        offered = {x["name"] for x in eh.arm_list("/providers/microsoft.aadiam/diagnosticSettingsCategories", tok,
                                                  api="2017-04-01")
                   if (x.get("properties") or {}).get("categoryType", "Logs") == "Logs"}
    except auth.HttpError:
        offered = set()
    wanted = [n for n in eh.ENTRA_CATEGORIES if not offered or n in offered]

    def put(categories):
        eh.arm("PUT", f"/providers/microsoft.aadiam/diagnosticSettings/{DIAG_NAME}", tok, api="2017-04-01", body={
            "properties": {"eventHubAuthorizationRuleId": rule_id, "eventHubName": hub,
                           "logs": [{"category": n, "enabled": True} for n in categories]}})

    try:
        put(wanted)
        return {"status": "on", "categories": wanted}
    except auth.HttpError as exc:
        if exc.status == 403:
            return {"status": "failed", "categories": [],
                    "reason": "The account is not Global or Security Administrator: Entra ID logs not streamed."}
        core = [n for n in eh.ENTRA_CORE if n in wanted]
        try:
            put(core)
            return {"status": "partial", "categories": core,
                    "reason": f"Licence-dependent categories refused; the {len(core)} core categories stream."}
        except auth.HttpError as exc2:
            return {"status": "failed", "categories": [], "reason": _arm_error(exc2.body)[:300]}


def _activity(tok, sub_id, rule_id, hub):
    current = discovery.probe_activity(tok, sub_id)
    for h in current.get("eventHubs", []):
        if h["rule"] == rule_id.lower() and h["hub"] == hub.lower():
            return "already", f"Already streams to {hub}."
    if len([n for n in current.get("settings", []) if n != DIAG_NAME]) >= 5:
        return "skipped", "Already has 5 Activity log settings (the Azure limit)."
    try:
        eh.arm("PUT", f"/subscriptions/{sub_id}/providers/Microsoft.Insights/diagnosticSettings/{DIAG_NAME}", tok,
               api=DIAG_API, body={"properties": {"eventHubAuthorizationRuleId": rule_id, "eventHubName": hub,
                                                  "logs": [{"category": c, "enabled": True}
                                                           for c in ACTIVITY_CATEGORIES]}})
        return "onboarded", ""
    except auth.HttpError as exc:
        return "failed", ("No permission on the subscription (needs Monitoring Contributor)." if exc.status == 403
                          else _arm_error(exc.body)[:300])


# --- 8. Results and connection test ---------------------------------------------------------

def _run_tests(creds):
    results = []
    for r in creds["regions"]:
        for name, fn, args in ((f"Event Hub · {r['display']}", eh.test_eventhub, (r["connectionString"], r["eventHub"])),
                               (f"Checkpoint container · {r['display']}", eh.test_storage,
                                (creds["storage"]["connectionString"], r["container"]))):
            try:
                ok, detail = fn(*args)
            except Exception as exc:  # noqa: BLE001
                ok, detail = False, f"{type(exc).__name__}: {exc}"
            results.append({"name": name, "ok": ok, "detail": detail})
    return {"ok": all(x["ok"] for x in results), "at": _now(), "results": results}


def api_test(form):
    cid = form.get("id", "")
    rec = _rec(cid)
    if not rec or not rec.get("credentials"):
        return _json({"error": "No connection strings for this onboarding."}, 404)
    tests = _run_tests(rec["credentials"])
    with _lock:
        rec["tests"] = tests
    _save(cid)
    return _json(tests)


# --- State, list, cancel, delete ------------------------------------------------------------

def api_state(q):
    cid = q.get("id", "")
    rec = _rec(cid)
    if rec is None:
        return _json({"error": "Unknown onboarding."}, 404)
    with _lock:
        out = json.loads(json.dumps(rec))
    out["live"] = _live(cid)
    out["minutesLeft"] = int((SESSIONS[cid]["until"] - time.time()) // 60) if out["live"] else 0
    out["hasDiscovery"] = cid in DISC
    out["log"] = out.get("log", [])[-60:]
    return _json(out)


def api_discovery(q):
    cid = q.get("id", "")
    if cid not in DISC:
        return _json({"error": "No scan in memory for this onboarding: sign in again."}, 404)
    return _json(DISC[cid]["client"])


def api_list(_q):
    rows = []
    for r in sorted(store.all_records(KIND), key=lambda x: x.get("createdAt", ""), reverse=True):
        res = r.get("results") or {}
        rows.append({"id": r["id"], "createdAt": r.get("createdAt"), "updatedAt": r.get("updatedAt"),
                     "phase": r.get("phase"), "signedInAs": r.get("signedInAs"),
                     "regions": len((r.get("plan") or {}).get("regions") or []),
                     "onboarded": res.get("onboarded"), "live": _live(r["id"])})
    return _json(rows)


def api_cancel(form):
    cid = form.get("id", "")
    rec = _rec(cid)
    if rec is None:
        return _json({"error": "Unknown onboarding."}, 404)
    with _lock:
        if rec.get("phase") not in ("done", "failed"):
            rec.update(cancelled=True, phase="cancelled",
                       error="Cancelled. Anything already deployed in Azure stays there (an ARM deployment that "
                             "had started completes in Azure).")
    _drop(cid, "cancelled")
    _save(cid)
    return _json({"ok": True})


def _delete(cid):
    with _lock:
        rec = RECS.get(cid)
        if rec is not None:
            rec["cancelled"] = True
    _drop(cid, "onboarding deleted")
    for state, req in list(PENDING.items()):
        if req["id"] == cid:
            PENDING.pop(state, None)
    with _lock:
        RECS.pop(cid, None)
        DISC.pop(cid, None)
        store.delete(KIND, cid)


def api_delete(form):
    cid = form.get("id", "")
    if form.get("all") == "1":
        recs = store.all_records(KIND)
        for r in recs:
            _delete(r["id"])
        return _json({"deleted": len(recs)})
    if not _rec(cid):
        return _json({"deleted": 0})
    _delete(cid)
    return _json({"deleted": 1})


ICON_DIR = UI_FILE.parent / "static" / "azure-icons"


def icon_route(q):
    """Official Azure architecture icons (unmodified), served locally: /az/icon?n=event-hubs."""
    name = q.get("n", "")
    path = ICON_DIR / f"{name}.svg"
    if not re.fullmatch(r"[a-z0-9-]{1,40}", name) or not path.is_file():
        return Raw("not found", "text/plain", status=404)
    return Raw(path.read_bytes(), "image/svg+xml", headers={"Cache-Control": "public, max-age=86400"})


def page_route(_q):
    html = UI_FILE.read_text(encoding="utf-8").replace("{{TARGET}}", TARGET_NAME)
    return Raw(html, "text/html; charset=utf-8")


GET_ROUTES = {"/": page_route, "/az": page_route, eh.CALLBACK_PATH: callback, "/az/api/state": api_state,
              "/az/api/discovery": api_discovery, "/az/api/list": api_list, "/az/icon": icon_route}
POST_ROUTES = {"/az/start": start, "/az/api/plan": api_plan, "/az/api/deploy": api_deploy,
               "/az/api/test": api_test, "/az/api/cancel": api_cancel, "/az/api/delete": api_delete}
