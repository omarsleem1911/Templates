#!/usr/bin/env node
"use strict";

const https         = require("https");
const path          = require("path");
const fs            = require("fs");
const { program }   = require("commander");
const axios         = require("axios");
const axiosRetry    = require("axios-retry").default;
const pLimit        = require("p-limit").default || require("p-limit");
const ExcelJS       = require("exceljs");
const { ClientSecretCredential }      = require("@azure/identity");
const { ResourceManagementClient }    = require("@azure/arm-resources");

// ========================= CONFIG ===========================================
const TENANT_ID     = process.env.TENANT_ID;
const CLIENT_ID     = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const OUT_DIR_ENV   = process.env.OUT_DIR;

if (!TENANT_ID || !CLIENT_ID || !CLIENT_SECRET) {
  console.error("Missing credentials. Fill in TENANT_ID, CLIENT_ID, CLIENT_SECRET.");
  process.exit(1);
}

const ARM         = "https://management.azure.com";
const OUT_DIR     = OUT_DIR_ENV || path.join(process.cwd(), "AzureDiagnosticsInventory");
const VERSION     = "AZ-Services-Discovery v4.0 (Node.js)";

const API_DIAG_RES  = "2021-05-01-preview";
const API_SQL_AUDIT = "2021-11-01";
const API_POLICY    = "2021-06-01";
const API_NETWORK   = "2024-05-01";
const API_SUB_DIAG  = "2021-05-01-preview";
const API_WEB_APPS  = "2023-12-01";

const MAX_WORKERS   = 80;   // tune up to 80 on fast networks
const HTTP_TIMEOUT  = 15000; // ms

const INCLUDE_STATUSES = new Set(["Enabled", "Disabled", "Not accessible"]);

const defaultExcludeTypes = [
  "microsoft.compute/disks",
  "microsoft.network/networkinterfaces",
  "microsoft.network/loadbalancers",
  "microsoft.network/privatednszones",
  "microsoft.insights/components",
  "microsoft.web/serverfarms",
  "microsoft.web/sites/slots",
  "microsoft.web/connections",
  "microsoft.operationalinsights/workspaces",
  "microsoft.streamanalytics/streamingjobs",
  "microsoft.eventgrid/systemtopics",
  "microsoft.app/containerapps",
  "microsoft.cognitiveservices/accounts/projects",
  "microsoft.insights/datacollectionrules",
];

const EXCLUDE_TYPES = process.env.EXCLUDE_TYPES !== undefined
  ? new Set(process.env.EXCLUDE_TYPES.split(',').filter(Boolean).map(s => s.trim().toLowerCase()))
  : new Set(defaultExcludeTypes);

const SERVICES_EXCLUDE_TYPES = new Set([
  "microsoft.compute/virtualmachines",
  "microsoft.hybridcompute/machines",
  "microsoft.compute/virtualmachinescalesets",
]);

const SQL_SERVER_TYPE        = "microsoft.sql/servers";
const STORAGE_ACCOUNT_TYPE   = "microsoft.storage/storageaccounts";
const VNET_TYPE              = "microsoft.network/virtualnetworks";
const APP_SERVICE_TYPE       = "microsoft.web/sites";

const STORAGE_SERVICES = [
  ["blobServices",  "Blob"],
  ["fileServices",  "File"],
  ["tableServices", "Table"],
  ["queueServices", "Queue"],
];

// ========================= OUTPUT FILE ======================================
fs.mkdirSync(OUT_DIR, { recursive: true });
const ts = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 13);
const OUTPUT_XLSX = path.join(OUT_DIR, `Azure_Services_Diagnostics_${ts}.xlsx`);

// ========================= AXIOS SETUP (connection pool + retry) =============
const httpsAgent = new https.Agent({
  keepAlive: true,
  maxSockets: MAX_WORKERS,
  maxFreeSockets: Math.floor(MAX_WORKERS / 2),
  timeout: HTTP_TIMEOUT,
});

const http = axios.create({
  timeout: HTTP_TIMEOUT,
  httpsAgent,
});

axiosRetry(http, {
  retries: 3,
  retryDelay: axiosRetry.exponentialDelay,
  retryCondition: (err) => {
    const status = err?.response?.status;
    return axiosRetry.isNetworkOrIdempotentRequestError(err) ||
           status === 429 || (status >= 500 && status <= 504);
  },
});

// ========================= BANNER / LOGGING ==================================
const ASCII_BANNER = `
    ___   ____     ___  _
   /   | /_  /    / _ \\(_)_____________   _____  _______  __
  / /| |  / /_   / // / (_-</ __/ _ \\ | / / -_)/ __/ // / /
 /_/ |_| /___/  /____/_/___/\\__/\\___/\\_,_/\\__/ _/  \\_, (_)
                                                  /___/
`;

function printBanner() {
  const now = new Date().toISOString().replace("T", " ").slice(0, 19);
  console.log(ASCII_BANNER);
  console.log("═".repeat(70));
  console.log("  🚀 Azure Services Diagnostics & Policy Inventory");
  console.log(`  📌 ${VERSION}  |  🕐 ${now}`);
  console.log("═".repeat(70));
  console.log();
}

function printStatusLine(label, value) {
  console.log(`${label.padEnd(12)}: ${value}`);
}
function printSection(title, icon = "📋") {
  console.log(`\n${"─".repeat(60)}`);
  console.log(`  ${icon} ${title}`);
  console.log("─".repeat(60));
}
function printSuccess(msg) { console.log(`  ✔ ${msg}`); }
function printInfo(msg)    { console.log(`  ℹ ${msg}`); }
function printWarning(msg) { console.log(`  ⚠ ${msg}`); }
function printError(msg)   { console.log(`  ✖ ${msg}`); }

let _lastProgressLine = "";
function printProgress(current, total, prefix = "Processing") {
  const pct     = total > 0 ? (current / total) * 100 : 0;
  const barLen  = 30;
  const filled  = total > 0 ? Math.floor((barLen * current) / total) : 0;
  const bar     = "█".repeat(filled) + "░".repeat(barLen - filled);
  const line    = `  ${prefix}: ${bar} ${current}/${total} (${pct.toFixed(1)}%)  `;
  process.stdout.write(`\r${line}`);
  if (current >= total) process.stdout.write("\n");
}

// ========================= HELPERS ==========================================
function extractRg(rid) {
  const parts = (rid || "").split("/");
  return parts[4] || "-";
}

function extractDestName(resourceId) {
  if (!resourceId) return "";
  const parts = resourceId.split("/");
  return parts[parts.length - 1] || resourceId;
}

function isExcluded(rtype) {
  const t = (rtype || "").toLowerCase();
  return EXCLUDE_TYPES.has(t);
}

function authHeader(token) {
  return { Authorization: `Bearer ${token}` };
}

async function httpGet(url, token) {
  try {
    const res = await http.get(url, { headers: authHeader(token) });
    return { status: res.status, data: res.data };
  } catch (err) {
    const status = err?.response?.status;
    if (status) return { status, data: err?.response?.data || null };
    return null; 
  }
}

// ========================= DIAGNOSTICS ======================================
function parseDiag(vals) {
  const destTypes = new Set();
  const destNames = new Set();
  const cats      = new Set();

  for (const v of vals || []) {
    const p = v?.properties || {};

    if (p.workspaceId) {
      destTypes.add("LogAnalytics");
      destNames.add(extractDestName(p.workspaceId));
    }
    if (p.eventHubAuthorizationRuleId) {
      destTypes.add("EventHub");
      const raw = p.eventHubAuthorizationRuleId;
      const lower = raw.toLowerCase();
      const ehName = p.eventHubName ||
        extractDestName(lower.includes("/authorizationrules/")
          ? raw.split(/\/authorizationrules\//i)[0]
          : raw);
      destNames.add(ehName);
    }
    if (p.storageAccountId) {
      destTypes.add("Storage");
      destNames.add(extractDestName(p.storageAccountId));
    }
    for (const l of p.logs || []) {
      if (l.enabled) cats.add(l.categoryGroup || l.category || "Unknown");
    }
    for (const m of p.metrics || []) {
      if (m.enabled) cats.add(m.category || "AllMetrics");
    }
  }

  return [
    [...destTypes].sort().join(", ") || "-",
    [...destNames].filter(Boolean).sort().join(", ") || "-",
    [...cats].sort().join(", ") || "-",
  ];
}

async function probeDiagStrict(resId, token) {
  const url = `${ARM}${resId}/providers/microsoft.insights/diagnosticSettings?api-version=${API_DIAG_RES}`;
  const r = await httpGet(url, token);
  if (!r) return null;
  if (r.status === 200) {
    const vals = r.data?.value || [];
    if (!vals.length) return ["Disabled", "-", "-", "-"];
    const [dt, dn, c] = parseDiag(vals);
    return ["Enabled", dt, dn, c];
  }
  if (r.status === 403) return ["Not accessible", "-", "-", "-"];
  return null;
}

// ========================= SQL AUDITING =====================================
async function probeSqlAuditing(resId, token) {
  const endpoints = [
    `${ARM}${resId}/auditingSettings/default?api-version=${API_SQL_AUDIT}`,
    `${ARM}${resId}/blobAuditingSettings/default?api-version=${API_SQL_AUDIT}`,
  ];
  for (const url of endpoints) {
    const r = await httpGet(url, token);
    if (!r) return null;
    if (r.status === 403) return ["Not accessible", "-", "SQL Auditing"];
    if (r.status === 200) {
      const props = r.data?.properties || {};
      const state = (props.state || "").toLowerCase();
      if (state === "enabled") {
        const dests = [];
        if (props.storageEndpoint) dests.push("Storage");
        if (props.isAzureMonitorTargetEnabled) dests.push("LogAnalytics");
        return ["Enabled", dests.length ? dests.join(", ") : "Configured", "SQL Auditing"];
      }
      return ["Disabled", "-", "SQL Auditing"];
    }
  }
  return null;
}

// ========================= VNET FLOW LOGS ===================================
async function getNetworkWatchers(subId, token) {
  const url = `${ARM}/subscriptions/${subId}/providers/Microsoft.Network/networkWatchers?api-version=${API_NETWORK}`;
  const r = await httpGet(url, token);
  return r?.status === 200 ? (r.data?.value || []) : [];
}

async function getFlowLogsForWatcher(subId, rg, watcherName, token) {
  const url = `${ARM}/subscriptions/${subId}/resourceGroups/${rg}/providers/Microsoft.Network/networkWatchers/${watcherName}/flowLogs?api-version=${API_NETWORK}`;
  const r = await httpGet(url, token);
  return r?.status === 200 ? (r.data?.value || []) : [];
}

async function fetchFlowLogsForSub(sub, token) {
  const results  = [];
  const watchers = await getNetworkWatchers(sub.subscriptionId, token);
  await Promise.all(watchers.map(async (watcher) => {
    const wId = watcher.id || "";
    if (!wId) return;
    const parts = wId.split("/");
    try {
      const rg          = parts[4];
      const watcherName = parts[parts.length - 1];
      const logs = await getFlowLogsForWatcher(sub.subscriptionId, rg, watcherName, token);
      results.push(...logs);
    } catch {  }
  }));
  return results;
}

async function collectAllFlowLogs(subsList, token) {
  const chunks = await Promise.all(subsList.map(s => fetchFlowLogsForSub(s, token)));
  return chunks.flat();
}

function probeVnetFlowLogs(resId, flowLogsCache) {
  for (const flowLog of flowLogsCache) {
    const targetId = (flowLog?.properties?.targetResourceId || "").toLowerCase();
    if (targetId !== resId.toLowerCase()) continue;

    const props   = flowLog.properties || {};
    const enabled = props.enabled === true;

    if (!enabled) return ["Disabled", "-", "-", "Flow Logs: Disabled, Traffic Analytics: N/A"];

    const dests = [], destNames = [];
    if (props.storageId) {
      dests.push("Storage");
      destNames.push(extractDestName(props.storageId));
    }
    const ta = props?.flowAnalyticsConfiguration?.networkWatcherFlowAnalyticsConfiguration || {};
    const taEnabled = ta.enabled === true;
    if (taEnabled && ta.workspaceResourceId) {
      dests.push("LogAnalytics");
      destNames.push(extractDestName(ta.workspaceResourceId));
    }
    const info = `Flow Logs: Enabled, Traffic Analytics: ${taEnabled ? "Enabled" : "Disabled"}`;
    return [
      "Enabled",
      dests.length ? dests.join(", ") : "Configured",
      destNames.length ? destNames.join(", ") : "-",
      info,
    ];
  }
  return ["Disabled", "-", "-", "Flow Logs: Disabled, Traffic Analytics: N/A"];
}

// ========================= ACTIVITY LOGS ====================================
async function probeSubscriptionActivityLogs(subId, subName, token) {
  const url = `${ARM}/subscriptions/${subId}/providers/Microsoft.Insights/diagnosticSettings?api-version=${API_SUB_DIAG}`;
  const r = await httpGet(url, token);
  if (!r) return null;
  const base = [subName, "-", "Subscription", `ActivityLogs (${subName})`, "-"];
  if (r.status === 200) {
    const vals = r.data?.value || [];
    if (!vals.length) return [...base, "Disabled",      "-", "-", "-", "-", "-"];
    const [dt, dn, c] = parseDiag(vals);
    return [...base, "Enabled", dt, dn, c, "-", "-"];
  }
  if (r.status === 403) return [...base, "Not accessible", "-", "-", "-", "-", "-"];
  return null;
}

// ========================= STORAGE SERVICES =================================
async function probeStorageService(storageId, servicePath, serviceLabel, token) {
  const serviceResId = `${storageId}/${servicePath}/default`;
  const url = `${ARM}${serviceResId}/providers/microsoft.insights/diagnosticSettings?api-version=${API_DIAG_RES}`;
  const r = await httpGet(url, token);
  if (!r) return null;
  if (r.status === 200) {
    const vals = r.data?.value || [];
    if (!vals.length) return [serviceLabel, "Disabled", "-", "-", "-"];
    const [dt, dn, c] = parseDiag(vals);
    return [serviceLabel, "Enabled", dt, dn, c];
  }
  if (r.status === 403) return [serviceLabel, "Not accessible", "-", "-", "-"];
  return null;
}

// ========================= APP SERVICE ======================================
async function probeAppServiceInfo(resId, token) {
  const url = `${ARM}${resId}?api-version=${API_WEB_APPS}`;
  const r = await httpGet(url, token);
  if (r?.status === 200) {
    const props = r.data?.properties || {};
    const hostnames = props.hostNames || [];
    return [hostnames.join(", ") || "-", props.state || "-"];
  }
  return ["-", "-"];
}

// ========================= UNIFIED TASK DISPATCH ============================
async function processTask(task, token) {
  const { kind } = task;

  if (kind === "regular") {
    const { subName, resId, rtype, rname, rlocation } = task;
    const rtypeLower = (rtype || "").toLowerCase();

    let domains  = "-";
    let appState = "-";
    if (rtypeLower === APP_SERVICE_TYPE) {
      [domains, appState] = await probeAppServiceInfo(resId, token);
    }

    if (rtypeLower === SQL_SERVER_TYPE) {
      const probe = await probeSqlAuditing(resId, token);
      if (!probe) return null;
      const [status, dests, cats] = probe;
      if (!INCLUDE_STATUSES.has(status)) return null;
      return [subName, extractRg(resId), rtype, rname, rlocation,
              status, dests, dests, cats, domains, appState];
    }

    const probe = await probeDiagStrict(resId, token);
    if (!probe) return null;
    const [status, destTypes, destNames, cats] = probe;
    if (!INCLUDE_STATUSES.has(status)) return null;
    return [subName, extractRg(resId), rtype, rname, rlocation,
            status, destTypes, destNames, cats, domains, appState];
  }

  if (kind === "storage") {
    const { subName, storageId, storageName, storageLoc, servicePath, serviceLabel } = task;
    const probe = await probeStorageService(storageId, servicePath, serviceLabel, token);
    if (!probe) return null;
    const [svcLabel, status, destTypes, destNames, cats] = probe;
    if (!INCLUDE_STATUSES.has(status)) return null;
    const rtype = `Microsoft.Storage/storageAccounts/${servicePath}`;
    const rname = `${storageName}/${svcLabel}`;
    return [subName, extractRg(storageId), rtype, rname, storageLoc,
            status, destTypes, destNames, cats, "-", "-"];
  }

  if (kind === "vnet") {
    const { subName, vnetId, vtype, vname, vloc, flowLogsCache } = task;
    const [status, destTypes, destNames, cats] = probeVnetFlowLogs(vnetId, flowLogsCache);
    if (!INCLUDE_STATUSES.has(status)) return null;
    return [subName, extractRg(vnetId), vtype, vname, vloc,
            status, destTypes, destNames, cats, "-", "-"];
  }

  if (kind === "activity_log") {
    return probeSubscriptionActivityLogs(task.subId, task.subName, token);
  }

  return null;
}

// ========================= POLICY COLLECTION ================================
async function fetchRemediation(subId, assignmentId, token) {
  const url = `${ARM}/subscriptions/${subId}/providers/Microsoft.PolicyInsights/remediations?api-version=2021-10-01`;
  const r = await httpGet(url, token);
  if (!r || r.status !== 200) return ["-", 0];
  let status = "-", count = 0;
  for (const rem of r.data?.value || []) {
    const rp = rem.properties || {};
    if ((rp.policyAssignmentId || "").toLowerCase() === assignmentId.toLowerCase()) {
      count++;
      if (rp.provisioningState) status = rp.provisioningState;
    }
  }
  return [status, count];
}

async function fetchCompliance(subId, assignmentId, token) {
  const url = `${ARM}/subscriptions/${subId}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01`;
  const r = await httpGet(url, token);
  if (!r || r.status !== 200) return ["-", 0, 0];
  for (const summary of r.data?.value || []) {
    for (const pa of summary.policyAssignments || []) {
      if ((pa.policyAssignmentId || "").toLowerCase() !== assignmentId.toLowerCase()) continue;
      const res     = pa.results || {};
      const details = res.resourceDetails || [{}];
      const comp    = details[0]?.count || 0;
      const ncomp   = res.nonCompliantResources || 0;
      const state   = ncomp > 0 ? "NonCompliant" : (comp > 0 ? "Compliant" : "-");
      return [state, comp, ncomp];
    }
  }
  return ["-", 0, 0];
}

async function processPolicyAssignment(sub, assignment, token) {
  const props        = assignment.properties || {};
  const assignmentId = assignment.id || "-";
  const policyDefId  = props.policyDefinitionId || "";
  const subId        = sub.subscriptionId;

  const [[remStatus, remCount], [compState, comp, ncomp]] = await Promise.all([
    fetchRemediation(subId, assignmentId, token),
    fetchCompliance(subId, assignmentId, token),
  ]);

  const scope = props.scope || assignmentId;
  let scopeType = "Other";
  if (scope.includes("/managementGroups/"))  scopeType = "Management Group";
  else if (scope.includes("/resourceGroups/")) scopeType = "Resource Group";
  else if (scope.includes("/subscriptions/"))  scopeType = "Subscription";

  const nonComplianceMsgs = (props.nonComplianceMessages || [])
    .map(m => m.message || "")
    .filter(Boolean)
    .join("; ") || "-";

  return {
    subscription:             sub.displayName,
    name:                     props.displayName || assignment.name || "-",
    assignment_id:            assignmentId,
    policy_definition_id:     policyDefId,
    policy_type:              policyDefId.includes("/providers/Microsoft.Authorization/policyDefinitions/")
                                ? "Built-in" : "Custom",
    scope,
    scope_type:               scopeType,
    enforcement_mode:         props.enforcementMode || "Default",
    compliance_state:         compState,
    compliant_resources:      comp,
    non_compliant_resources:  ncomp,
    parameters:               Object.keys(props.parameters || {}).length
                                ? JSON.stringify(props.parameters, null, 2) : "-",
    non_compliance_messages:  nonComplianceMsgs,
    remediation_status:       remStatus,
    remediation_tasks_count:  remCount,
    description:              props.description || "-",
    created_by:               props.metadata?.createdBy || "-",
    created_on:               props.metadata?.createdOn || "-",
  };
}

async function collectPolicies(token, subsList) {
  const allAssignments = [];
  for (const sub of subsList) {
    const url = `${ARM}/subscriptions/${sub.subscriptionId}/providers/Microsoft.Authorization/policyAssignments?api-version=${API_POLICY}`;
    const r = await httpGet(url, token);
    if (r?.status === 200) {
      for (const a of r.data?.value || []) {
        allAssignments.push([sub, a]);
      }
    }
  }

  const total = allAssignments.length;
  if (total === 0) return [];
  printSection(`Collecting Policies (${total} found)`, "📜");

  const limit    = pLimit(MAX_WORKERS);
  let processed  = 0;
  const policies = [];

  await Promise.all(allAssignments.map(([sub, assignment]) =>
    limit(async () => {
      try {
        const p = await processPolicyAssignment(sub, assignment, token);
        policies.push(p);
      } catch { }
      processed++;
      printProgress(processed, total, "Scanning policies");
    })
  ));

  printSuccess("Policy collection complete!");
  return policies;
}

// ========================= EXCEL HELPERS ====================================
const HEAD_FILL = { type: "pattern", pattern: "solid", fgColor: { argb: "FF1F4E78" } };
const HEAD_FONT = { color: { argb: "FFFFFFFF" }, bold: true };

function applyHeadStyle(row) {
  row.eachCell(cell => {
    cell.fill = HEAD_FILL;
    cell.font = HEAD_FONT;
  });
}

function autosizeColumns(worksheet) {
  worksheet.columns.forEach(col => {
    let max = 10;
    col.eachCell({ includeEmpty: false }, cell => {
      const len = cell.value ? String(cell.value).length : 0;
      if (len > max) max = len;
    });
    col.width = Math.min(max + 2, 80);
  });
}

function colorStatusCells(worksheet, statusColIdx) {
  worksheet.eachRow((row, rowNum) => {
    if (rowNum < 2) return;
    const cell = row.getCell(statusColIdx);
    const v    = (cell.value || "").trim();
    if (v === "Enabled")        cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFC6EFCE" } };
    else if (v === "Disabled")  cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFFFC7CE" } };
    else if (v === "Not accessible") cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFFFEB9C" } };
  });
}

function colorComplianceCells(worksheet, compColIdx) {
  worksheet.eachRow((row, rowNum) => {
    if (rowNum < 2) return;
    const cell = row.getCell(compColIdx);
    const v    = (cell.value || "").trim().toLowerCase();
    if (v === "compliant")        cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFC6EFCE" } };
    else if (v === "noncompliant" || v === "non-compliant")
                                  cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFFFC7CE" } };
    else if (v === "exempt")      cell.fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFBDD7EE" } };
  });
}

function buildPoliciesSheet(workbook, policies) {
  const ws = workbook.addWorksheet("Azure Policies");
  const headers = [
    "Subscription", "Policy Name", "Policy Type", "Scope Type", "Scope",
    "Enforcement Mode", "Compliance State", "Compliant Resources", "Non-Compliant Resources",
    "Remediation Status", "Remediation Tasks", "Parameters", "Non-Compliance Messages",
    "Description", "Created By", "Created On", "Policy Definition ID", "Assignment ID",
  ];
  const headRow = ws.addRow(headers);
  applyHeadStyle(headRow);

  for (const p of policies) {
    ws.addRow([
      p.subscription, p.name, p.policy_type, p.scope_type, p.scope,
      p.enforcement_mode, p.compliance_state, p.compliant_resources,
      p.non_compliant_resources, p.remediation_status, p.remediation_tasks_count,
      p.parameters, p.non_compliance_messages, p.description,
      p.created_by, p.created_on, p.policy_definition_id, p.assignment_id,
    ]);
  }
  colorComplianceCells(ws, 7);
  autosizeColumns(ws);
  return ws;
}

function buildOverview(workbook, totalRows, summaryByType, policyCount) {
  const ws = workbook.addWorksheet("Overview");
  workbook.views = [{ activeTab: workbook.worksheets.findIndex(w => w.name === "Overview") }];

  const h1 = ws.addRow(["Metric", "Value"]);
  applyHeadStyle(h1);

  ws.addRow(["Total Resources Listed",    totalRows]);
  ws.addRow(["Distinct Types (Listed)",   summaryByType.size]);
  ws.addRow(["Total Policy Assignments",  policyCount]);
  ws.addRow([]);
  ws.addRow(["Summary by Type"]);
  ws.addRow([]);

  const h2 = ws.addRow(["Type", "Total (Listed)", "Enabled", "Disabled", "Not accessible"]);
  applyHeadStyle(h2);

  const items = [...summaryByType.entries()]
    .map(([t, counts]) => [
      t,
      counts.total || 0,
      counts.Enabled || 0,
      counts.Disabled || 0,
      counts["Not accessible"] || 0,
    ])
    .sort((a, b) => b[1] - a[1]);

  for (const row of items) {
    const r = ws.addRow(row);
    r.getCell(3).fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFC6EFCE" } };
    r.getCell(4).fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFFFC7CE" } };
    r.getCell(5).fill = { type: "pattern", pattern: "solid", fgColor: { argb: "FFFFEB9C" } };
  }

  ws.autoFilter = null;
  autosizeColumns(ws);
  return ws;
}

// ========================= MAIN =============================================
async function main(scanPolicies = false) {
  printBanner();

  let cred, token;
  try {
    cred  = new ClientSecretCredential(TENANT_ID, CLIENT_ID, CLIENT_SECRET);
    token = (await cred.getToken("https://management.azure.com/.default")).token;
    printStatusLine("AUTH", "OK");
  } catch {
    printStatusLine("AUTH", "FAILED");
    printError("Authentication failed. Exiting.");
    process.exit(1);
  }

  async function refreshToken() {
    return (await cred.getToken("https://management.azure.com/.default")).token;
  }

  const subsList  = [];
  const subsUrl = `${ARM}/subscriptions?api-version=2020-01-01`;
  const subsRes = await httpGet(subsUrl, token);
  if (subsRes && subsRes.status === 200) {
    for (const s of subsRes.data?.value || []) {
      subsList.push({ subscriptionId: s.subscriptionId, displayName: s.displayName });
    }
  } else {
    printError("Failed to fetch subscriptions. Check permissions.");
    process.exit(1);
  }
  
  printStatusLine("SUBS",    String(subsList.length));
  printStatusLine("WORKERS", String(MAX_WORKERS));

  token = await refreshToken(); 

  printInfo("Pre-fetching VNet flow logs …");
  const flowLogsCache = await collectAllFlowLogs(subsList, token);
  printInfo(`Flow log entries cached: ${flowLogsCache.length}`);

  const allTasks = [];

  for (const sub of subsList) {
    const rmClient = new ResourceManagementClient(cred, sub.subscriptionId);

    for await (const r of rmClient.resources.list()) {
      const rtypeLower = (r.type || "").toLowerCase();

      if (SERVICES_EXCLUDE_TYPES.has(rtypeLower) || isExcluded(rtypeLower)) continue;

      if (rtypeLower === STORAGE_ACCOUNT_TYPE) {
        for (const [servicePath, serviceLabel] of STORAGE_SERVICES) {
          allTasks.push({
            kind: "storage",
            subName: sub.displayName, storageId: r.id,
            storageName: r.name, storageLoc: r.location,
            servicePath, serviceLabel,
          });
        }
        continue;
      }

      if (rtypeLower === VNET_TYPE) {
        allTasks.push({
          kind: "vnet",
          subName: sub.displayName, subId: sub.subscriptionId,
          vnetId: r.id, vtype: r.type, vname: r.name, vloc: r.location,
          flowLogsCache,
        });
        continue;
      }

      allTasks.push({
        kind: "regular",
        subName: sub.displayName,
        resId: r.id, rtype: r.type, rname: r.name, rlocation: r.location,
      });
    }

    allTasks.push({ kind: "activity_log", subId: sub.subscriptionId, subName: sub.displayName });
  }

  const total = allTasks.length;
  printStatusLine("RESOURCES", String(total));
  printSection(`Processing ${total} tasks (${MAX_WORKERS} workers)`, "⚡");

  const workbook = new ExcelJS.Workbook();
  const wsSrv    = workbook.addWorksheet("Azure Services");

  const srvHeaders = [
    "Subscription", "RG", "Type", "Name", "Location",
    "Status", "Destination Types", "Destination Names",
    "Categories", "Domains", "App State",
  ];
  const srvHeadRow = wsSrv.addRow(srvHeaders);
  applyHeadStyle(srvHeadRow);

  const summaryByType = new Map();  
  let processed = 0;
  const rows = [];

  const limit = pLimit(MAX_WORKERS);

  await Promise.all(allTasks.map(task =>
    limit(async () => {
      try {
        const result = await processTask(task, token);
        if (result) {
          const [, , rtype, , , status] = result;
          if (INCLUDE_STATUSES.has(status)) {
            const key = (rtype || "").toLowerCase();
            if (!summaryByType.has(key)) summaryByType.set(key, { total: 0, Enabled: 0, Disabled: 0, "Not accessible": 0 });
            const bucket = summaryByType.get(key);
            bucket.total++;
            bucket[status] = (bucket[status] || 0) + 1;
            rows.push(result);
          }
        }
      } catch { }
      processed++;
      printProgress(processed, total, "Checking diagnostics");
    })
  ));

  for (const row of rows) wsSrv.addRow(row);
  printSuccess("Resource diagnostics check complete!");

  colorStatusCells(wsSrv, 6);
  autosizeColumns(wsSrv);
  wsSrv.autoFilter = { from: "A1", to: { row: 1, column: srvHeaders.length } };

  let policies = [];
  if (scanPolicies) {
    token    = await refreshToken();
    policies = await collectPolicies(token, subsList);
    buildPoliciesSheet(workbook, policies);
    printStatusLine("POLICY", String(policies.length));
  } else {
    printStatusLine("POLICY", "SKIPPED (use --policy flag)");
  }

  buildOverview(workbook, rows.length, summaryByType, policies.length);

  await workbook.xlsx.writeFile(OUTPUT_XLSX);
  printStatusLine("OUTPUT", path.basename(OUTPUT_XLSX));
  printStatusLine("STATUS", "SUCCESS");
  console.log();
}

// ========================= CLI ==============================================
program
  .name("az-services-discovery")
  .description("Azure Services Diagnostics & Policy Inventory Tool")
  .option("--policy", "Include Azure Policy scanning in the inventory")
  .parse(process.argv);

const opts = program.opts();
main(opts.policy === true).catch(err => {
  printError(`Fatal: ${err.message}`);
  process.exit(1);
});
