"""Azure environment discovery: a Python port of the team's az_services_discovery_v4.js.

Kept from the original scanner:
  * the excluded resource types (no useful logs, or noise) and the VM / scale-set / Arc types
    that need an agent rather than a diagnostic setting;
  * storage accounts are checked per service (blob, file, table, queue): the account itself
    has metrics only, the logs are on the services;
  * the current diagnostic settings of every resource (Enabled / Disabled / Not accessible,
    with destination types, destination names and categories);
  * SQL servers through their auditing settings, VNets through Network Watcher flow logs;
  * the subscription Activity log settings;
  * bounded parallel workers with retry on 429 / 5xx (eventhub.arm retries).

Changed for the Hub: it runs with the admin's delegated ARM token (no client secret), lists
resources through Azure Resource Graph (one query for every subscription, with the
per-subscription listing as a fallback), and returns data for the Scan / Select screens
instead of writing an Excel workbook. The Azure Policy scan is not ported (not needed here).
"""

import concurrent.futures

from . import auth
from .eventhub import arm, arm_list

API_DIAG = "2021-05-01-preview"
API_SQL_AUDIT = "2021-11-01"
API_NETWORK = "2024-05-01"
API_SUBS = "2022-12-01"
WORKERS = 16

# From the original scanner: types skipped by default.
EXCLUDE_TYPES = {
    "microsoft.compute/disks", "microsoft.network/networkinterfaces", "microsoft.network/loadbalancers",
    "microsoft.network/privatednszones", "microsoft.insights/components", "microsoft.web/serverfarms",
    "microsoft.web/sites/slots", "microsoft.web/connections", "microsoft.operationalinsights/workspaces",
    "microsoft.streamanalytics/streamingjobs", "microsoft.eventgrid/systemtopics", "microsoft.app/containerapps",
    "microsoft.cognitiveservices/accounts/projects", "microsoft.insights/datacollectionrules",
}
# From the original scanner: compute that is not onboarded through diagnostic settings.
AGENT_TYPES = {"microsoft.compute/virtualmachines", "microsoft.hybridcompute/machines",
               "microsoft.compute/virtualmachinescalesets"}

STORAGE_TYPE = "microsoft.storage/storageaccounts"
VNET_TYPE = "microsoft.network/virtualnetworks"
SQL_SERVER_TYPE = "microsoft.sql/servers"
STORAGE_SERVICES = [("blobServices", "Blob"), ("fileServices", "File"),
                    ("tableServices", "Table"), ("queueServices", "Queue")]

GRAPH_QUERY = ("resources "
               "| where isempty(tostring(tags['cor-integration'])) "
               "| project id, name, type = tolower(type), kind = tolower(kind), location = tolower(location), "
               "subscriptionId, resourceGroup "
               "| order by id asc")


# --- Inventory ---------------------------------------------------------------------------

def subscriptions(tok):
    return [s for s in arm_list("/subscriptions", tok, api=API_SUBS) if s.get("state") == "Enabled"]


def locations(tok, sub_id):
    try:
        return {x["name"]: x.get("displayName") or x["name"]
                for x in arm_list(f"/subscriptions/{sub_id}/locations", tok, api=API_SUBS)}
    except auth.HttpError:
        return {}


def list_resources(tok, sub_ids, progress=lambda found, total: None):
    """Every resource in the subscriptions (cor.'s own, tagged cor-integration, left out)."""
    try:
        return _graph(tok, sub_ids, progress)
    except auth.HttpError:
        return _per_subscription(tok, sub_ids, progress)


def _graph(tok, sub_ids, progress):
    out = []
    for i in range(0, len(sub_ids), 1000):  # Resource Graph takes up to 1000 subscriptions a call
        chunk, skip = sub_ids[i:i + 1000], None
        while True:
            options = {"$top": 1000, "resultFormat": "objectArray"}
            if skip:
                options["$skipToken"] = skip
            resp = arm("POST", "/providers/Microsoft.ResourceGraph/resources", tok, api="2022-10-01",
                       body={"subscriptions": chunk, "query": GRAPH_QUERY, "options": options}) or {}
            out += resp.get("data") or []
            progress(len(out), resp.get("totalRecords"))
            skip = resp.get("$skipToken")
            if not skip:
                break
    return out


def _per_subscription(tok, sub_ids, progress):
    """The original scanner's method: list resources subscription by subscription."""
    out = []
    for sub in sub_ids:
        for r in arm_list(f"/subscriptions/{sub}/resources", tok, api="2021-04-01"):
            if (r.get("tags") or {}).get("cor-integration"):
                continue
            parts = r["id"].split("/")
            out.append({"id": r["id"], "name": r.get("name"), "type": (r.get("type") or "").lower(),
                        "kind": (r.get("kind") or "").lower(), "location": (r.get("location") or "").lower(),
                        "subscriptionId": sub, "resourceGroup": parts[4] if len(parts) > 4 else ""})
        progress(len(out), None)
    return out


# --- Current logging state (the original scanner's probes) --------------------------------

def _last(resource_id):
    return (resource_id or "").rstrip("/").split("/")[-1]


def parse_diag(values):
    """parseDiag: destination types, destination names and enabled categories of the
    resource's diagnostic settings, plus the event hubs they already stream to."""
    types, names, cats, hubs, setting_names = set(), set(), set(), [], []
    for v in values or []:
        p = v.get("properties") or {}
        setting_names.append(v.get("name"))
        if p.get("workspaceId"):
            types.add("LogAnalytics")
            names.add(_last(p["workspaceId"]))
        if p.get("eventHubAuthorizationRuleId"):
            types.add("EventHub")
            rule = p["eventHubAuthorizationRuleId"]
            ns = rule.lower().split("/authorizationrules/")[0]
            names.add(p.get("eventHubName") or _last(ns))
            hubs.append({"rule": rule.lower(), "hub": (p.get("eventHubName") or "").lower(), "setting": v.get("name")})
        if p.get("storageAccountId"):
            types.add("Storage")
            names.add(_last(p["storageAccountId"]))
        for log in p.get("logs") or []:
            if log.get("enabled"):
                cats.add(log.get("categoryGroup") or log.get("category") or "Unknown")
    return {"destTypes": sorted(types), "destNames": sorted(n for n in names if n), "categories": sorted(cats),
            "eventHubs": hubs, "settings": [n for n in setting_names if n]}


def probe_diag(tok, target_id):
    """probeDiagStrict for one resource (or storage service)."""
    try:
        resp = arm("GET", f"{target_id}/providers/microsoft.insights/diagnosticSettings", tok, api=API_DIAG,
                   attempts=3) or {}
    except auth.HttpError as exc:
        if exc.status == 403:
            return {"status": "Not accessible"}
        return {"status": "Unknown", "reason": str(exc)[:200]}
    except OSError as exc:
        return {"status": "Unknown", "reason": str(exc)[:200]}
    values = resp.get("value") or []
    if not values:
        return {"status": "Disabled"}
    return {"status": "Enabled", **parse_diag(values)}


def probe_sql_auditing(tok, server_id):
    """probeSqlAuditing: server auditing state and destinations."""
    for path in ("auditingSettings/default", "blobAuditingSettings/default"):
        try:
            props = (arm("GET", f"{server_id}/{path}", tok, api=API_SQL_AUDIT, attempts=3) or {}).get("properties") or {}
        except auth.HttpError as exc:
            if exc.status == 403:
                return {"status": "Not accessible", "categories": ["SQL Auditing"]}
            continue
        except OSError:
            continue
        if (props.get("state") or "").lower() == "enabled":
            dests = (["Storage"] if props.get("storageEndpoint") else []) + \
                    (["AzureMonitor"] if props.get("isAzureMonitorTargetEnabled") else [])
            return {"status": "Enabled", "destTypes": dests or ["Configured"], "categories": ["SQL Auditing"],
                    "azureMonitor": bool(props.get("isAzureMonitorTargetEnabled"))}
        return {"status": "Disabled", "categories": ["SQL Auditing"]}
    return {"status": "Unknown"}


def flow_logs(tok, sub_ids):
    """collectAllFlowLogs: every Network Watcher flow log, keyed by its target resource."""
    out = {}
    for sub in sub_ids:
        try:
            watchers = arm_list(f"/subscriptions/{sub}/providers/Microsoft.Network/networkWatchers", tok,
                                api=API_NETWORK)
        except (auth.HttpError, OSError):
            continue
        for w in watchers:
            try:
                for fl in arm_list(f"{w['id']}/flowLogs", tok, api=API_NETWORK):
                    target = ((fl.get("properties") or {}).get("targetResourceId") or "").lower()
                    if target:
                        out[target] = fl.get("properties") or {}
            except (auth.HttpError, OSError):
                continue
    return out


def probe_vnet(vnet_id, flowlog_cache):
    """probeVnetFlowLogs."""
    props = flowlog_cache.get(vnet_id.lower())
    if not props or props.get("enabled") is not True:
        return {"status": "Disabled", "categories": ["Flow Logs"]}
    dests, names = [], []
    if props.get("storageId"):
        dests.append("Storage")
        names.append(_last(props["storageId"]))
    ta = (props.get("flowAnalyticsConfiguration") or {}).get("networkWatcherFlowAnalyticsConfiguration") or {}
    if ta.get("enabled") and ta.get("workspaceResourceId"):
        dests.append("LogAnalytics")
        names.append(_last(ta["workspaceResourceId"]))
    return {"status": "Enabled", "destTypes": dests or ["Configured"], "destNames": names,
            "categories": ["Flow Logs", "Traffic Analytics" if ta.get("enabled") else "No Traffic Analytics"]}


def probe_resource(tok, r, flowlog_cache):
    """The current logging state of one resource, the way the original scanner reads it."""
    rtype = r["type"]
    if rtype == STORAGE_TYPE:
        services = {label: probe_diag(tok, f"{r['id']}/{path}/default") for path, label in STORAGE_SERVICES}
        states = {s["status"] for s in services.values()}
        status = ("Enabled" if "Enabled" in states else "Not accessible" if "Not accessible" in states
                  else "Disabled" if "Disabled" in states else "Unknown")
        merged = {"status": status, "services": {k: v["status"] for k, v in services.items()},
                  "eventHubs": [h for s in services.values() for h in s.get("eventHubs", [])],
                  "destTypes": sorted({t for s in services.values() for t in s.get("destTypes", [])}),
                  "destNames": sorted({t for s in services.values() for t in s.get("destNames", [])})}
        return merged
    if rtype == VNET_TYPE:
        return probe_vnet(r["id"], flowlog_cache)
    if rtype == SQL_SERVER_TYPE:
        return probe_sql_auditing(tok, r["id"])
    return probe_diag(tok, r["id"])


def probe_all(tok, resources, flowlog_cache, progress=lambda done, total: None, workers=WORKERS):
    """Probe every resource with bounded parallel workers (the original's p-limit pool)."""
    results = [None] * len(resources)
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(probe_resource, tok, r, flowlog_cache): i for i, r in enumerate(resources)}
        for f in concurrent.futures.as_completed(futures):
            i = futures[f]
            try:
                results[i] = f.result()
            except Exception as exc:  # one resource never stops the scan
                results[i] = {"status": "Unknown", "reason": f"{type(exc).__name__}: {exc}"[:200]}
            done += 1
            if done % 25 == 0 or done == len(resources):
                progress(done, len(resources))
    return results


def probe_activity(tok, sub_id):
    """probeSubscriptionActivityLogs."""
    try:
        resp = arm("GET", f"/subscriptions/{sub_id}/providers/Microsoft.Insights/diagnosticSettings", tok,
                   api=API_DIAG, attempts=3) or {}
    except auth.HttpError as exc:
        return {"status": "Not accessible" if exc.status == 403 else "Unknown"}
    values = resp.get("value") or []
    return {"status": "Enabled", **parse_diag(values)} if values else {"status": "Disabled"}


def probe_entra(tok):
    """Entra ID (tenant) diagnostic settings: readable by Global / Security Administrators."""
    try:
        values = arm_list("/providers/microsoft.aadiam/diagnosticSettings", tok, api="2017-04-01")
    except auth.HttpError as exc:
        return {"status": "Not accessible" if exc.status == 403 else "Unknown"}
    return {"status": "Enabled", **parse_diag(values)} if values else {"status": "Disabled"}
