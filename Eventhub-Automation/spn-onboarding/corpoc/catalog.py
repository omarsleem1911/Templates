"""Capabilities and the permissions behind them.

Mirrors the capability catalog of provision-azure-spn-v3.2.ps1 so the PoCs grant
exactly what the script grants. Permissions are listed by NAME and resolved to
IDs in the tenant at run time.
"""

from dataclasses import dataclass, field

# Resource (API) application IDs, the same in every tenant.
API = {
    "Graph": "00000003-0000-0000-c000-000000000000",          # Microsoft Graph
    "Exchange": "00000002-0000-0ff1-ce00-000000000000",       # Office 365 Exchange Online
    "Management": "c5393580-f805-4401-95e8-94b7a6ef2fc2",     # Office 365 Management APIs
    "SharePoint": "00000003-0000-0ff1-ce00-000000000000",     # Office 365 SharePoint Online
    "DefenderATP": "fc780465-2017-40d4-a0c5-307022471b92",    # WindowsDefenderATP (MDE)
    "ThreatProtect": "8ee8fdad-f234-4243-8f3b-15c294843740",  # Microsoft Threat Protection (Defender XDR)
}

# Token audience per API, for verification with the SPN's own credentials.
# None: not verified by the PoC (SharePoint app-only needs a certificate).
AUDIENCE = {
    "Graph": "https://graph.microsoft.com",
    "Exchange": "https://outlook.office365.com",
    "Management": "https://manage.office.com",
    "SharePoint": None,
    "DefenderATP": "https://api.securitycenter.microsoft.com",
    "ThreatProtect": "https://api.security.microsoft.com",
}

# Microsoft's first-party message trace app: its service principal must exist
# in the tenant before the Graph message trace API accepts calls.
MESSAGE_TRACE_APP_ID = "8bd644d1-64a1-4d4b-ae52-2e0cbf64e373"

# Built-in directory role given to the SPN for basic email response.
EXCHANGE_ADMIN_ROLE_ID = "29232cdf-9323-42fd-ade2-1d097af3e4de"


@dataclass(frozen=True)
class Capability:
    key: str
    title: str
    description: str
    perms: dict                      # API key -> tuple of permission names
    test: tuple | None = None        # (API key, path) read call used to verify
    response: bool = False           # True: changes things in the tenant
    needs: tuple = field(default=())  # extra setup outside API permissions


CAPABILITIES = [
    Capability("m365audit", "Microsoft 365 audit logs",
               "Unified audit log (Exchange, SharePoint, Teams, Entra, DLP) and service health.",
               {"Management": ("ActivityFeed.Read", "ActivityFeed.ReadDlp", "ServiceHealth.Read")},
               ("Management", "/api/v1.0/{tenant}/activity/feed/subscriptions/list")),
    Capability("entra", "Entra ID sign-ins and audit",
               "Sign-in and directory audit logs, risky users and risk detections.",
               {"Graph": ("AuditLog.Read.All", "Directory.Read.All", "IdentityRiskEvent.Read.All",
                          "IdentityRiskyUser.Read.All", "IdentityRiskyServicePrincipal.Read.All", "Reports.Read.All")},
               ("Graph", "/v1.0/auditLogs/directoryAudits?$top=1")),
    Capability("defender", "Defender XDR alerts and incidents",
               "Defender XDR alerts and incidents, advanced hunting. Read-only.",
               {"Graph": ("SecurityAlert.Read.All", "SecurityIncident.Read.All", "SecurityEvents.Read.All",
                          "SecurityActions.Read.All", "ThreatHunting.Read.All"),
                "ThreatProtect": ("AdvancedHunting.Read.All", "Incident.Read.All")},
               ("Graph", "/v1.0/security/alerts_v2?$top=1")),
    Capability("mde", "Defender for Endpoint data",
               "Devices, alerts, software, vulnerabilities, recommendations and indicators.",
               {"DefenderATP": ("AdvancedQuery.Read.All", "Alert.Read.All", "Machine.Read.All", "File.Read.All",
                                "Ip.Read.All", "RemediationTasks.Read.All", "Score.Read.All",
                                "SecurityBaselinesAssessment.Read.All", "SecurityConfiguration.Read.All",
                                "SecurityRecommendation.Read.All", "Software.Read.All", "Ti.Read.All",
                                "Url.Read.All", "User.Read.All", "Vulnerability.Read.All")},
               ("DefenderATP", "/api/machines?$top=1")),
    Capability("mailflow", "Mail flow / message trace",
               "Exchange Online message trace through Graph. No mail content.",
               {"Graph": ("ExchangeMessageTrace.Read.All",), "Exchange": ("ReportingWebService.Read.All",)},
               ("Graph", "/v1.0/admin/exchange/tracing/messageTraces?$top=1"),
               needs=("message-trace-sp",)),
    Capability("purview", "Microsoft Purview audit search",
               "Purview audit log searches (Entra, Exchange, SharePoint, OneDrive, Endpoint, Dynamics).",
               {"Graph": ("AuditLogsQuery.Read.All", "AuditLogsQuery-CRM.Read.All", "AuditLogsQuery-Endpoint.Read.All",
                          "AuditLogsQuery-Entra.Read.All", "AuditLogsQuery-Exchange.Read.All",
                          "AuditLogsQuery-OneDrive.Read.All", "AuditLogsQuery-SharePoint.Read.All")},
               ("Graph", "/beta/security/auditLog/queries?$top=1")),
    Capability("intune", "Intune audit events",
               "Intune audit events and device management configuration.",
               {"Graph": ("DeviceManagementApps.Read.All", "DeviceManagementConfiguration.Read.All")},
               ("Graph", "/v1.0/deviceManagement/auditEvents?$top=1")),
    Capability("threatintel", "Threat intelligence",
               "Threat indicators and Microsoft Defender Threat Intelligence.",
               {"Graph": ("ThreatIndicators.Read.All", "ThreatIntelligence.Read.All")}),
    Capability("directory", "Directory lookups",
               "Users, groups, members, app registrations and delegated grants, for investigations.",
               {"Graph": ("User.Read.All", "User.ReadBasic.All", "Group.Read.All", "GroupMember.Read.All",
                          "Application.Read.All", "DelegatedPermissionGrant.Read.All", "Directory.Read.All")},
               ("Graph", "/v1.0/users?$top=1&$select=id")),
    Capability("sharepoint", "SharePoint / OneDrive sites (read)",
               "SharePoint and OneDrive sites and files, read-only.",
               {"SharePoint": ("Sites.Read.All",)}),
    # Response capabilities: these CHANGE things in the tenant. Not exercised by the PoC.
    Capability("endpoint", "Endpoint response",
               "Isolate, scan, restrict and offboard devices, live response, stop & quarantine files.",
               {"DefenderATP": ("Alert.ReadWrite.All", "Machine.CollectForensics", "Machine.Isolate",
                                "Machine.LiveResponse", "Machine.Offboard", "Machine.RestrictExecution",
                                "Machine.Scan", "Machine.StopAndQuarantine", "Ti.ReadWrite", "Ti.ReadWrite.All"),
                "ThreatProtect": ("Incident.ReadWrite.All", "CustomDetections.ReadWrite.All"),
                "Graph": ("ThreatIndicators.ReadWrite.OwnedBy",)},
               response=True),
    Capability("identity", "Identity response",
               "Disable/enable users, revoke sessions, reset passwords, change group membership.",
               {"Graph": ("User.EnableDisableAccount.All", "User.RevokeSessions.All",
                          "User-PasswordProfile.ReadWrite.All", "GroupMember.ReadWrite.All")},
               response=True),
    Capability("emailbasic", "Basic email response",
               "Exchange Online PowerShell as the app (block senders, purge messages); needs the Exchange Administrator role.",
               {"Exchange": ("Exchange.ManageAsApp",)},
               response=True, needs=("exchange-admin-role",)),
]

BY_KEY = {c.key: c for c in CAPABILITIES}
READ_KEYS = [c.key for c in CAPABILITIES if not c.response]


def parse_caps(raw):
    """'all' (every read capability) or a comma list of keys."""
    items = raw if isinstance(raw, (list, tuple)) else str(raw or "").split(",")
    keys = [k.strip().lower() for k in items if k and k.strip()]
    if "all" in keys:
        keys = READ_KEYS + [k for k in keys if k != "all" and k not in READ_KEYS]
    unknown = [k for k in keys if k not in BY_KEY]
    if unknown:
        raise ValueError(f"unknown capability: {', '.join(unknown)} (valid: all, {', '.join(BY_KEY)})")
    if not keys:
        raise ValueError("choose at least one capability")
    return list(dict.fromkeys(keys))


def perms_for(keys):
    """API key -> sorted unique permission names for the chosen capabilities."""
    out = {}
    for k in keys:
        for api, names in BY_KEY[k].perms.items():
            out.setdefault(api, set()).update(names)
    return {api: sorted(names) for api, names in out.items()}
