<#
.SYNOPSIS
  Cancels the test subscriptions made by create-test-subscriptions.ps1.

.DESCRIPTION
  Finds the subscription aliases whose name starts with the prefix (default "cortest-sub"),
  lists them, asks you to type CANCEL, then for each one:
    1. removes the "corlogging" Activity log diagnostic setting (if the portal created it);
    2. deletes every resource group in it (Azure requires an empty subscription to cancel);
    3. cancels the subscription and removes its alias.
  A cancelled subscription is disabled at once and permanently deleted by Microsoft after about
  90 days (until then the billing account owner can reactivate it in the portal).

.EXAMPLE
  ./cancel-test-subscriptions.ps1
#>
param(
    [string]$Prefix = "cortest-sub",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Arm([string]$Method, [string]$Path, $Body) {
    $call = @{ Method = $Method; Path = $Path }
    if ($Body) { $call.Payload = ($Body | ConvertTo-Json -Depth 10) }
    $r = Invoke-AzRestMethod @call
    $content = if ($r.Content) { $r.Content | ConvertFrom-Json } else { $null }
    if ($r.StatusCode -ge 400) {
        $msg = if ($content.error) { "$($content.error.code): $($content.error.message)" } else { $r.Content }
        throw "HTTP $($r.StatusCode) on $Method $($Path.Split('?')[0]) - $msg"
    }
    return $content
}

$aliases = @((Arm GET "/providers/Microsoft.Subscription/aliases?api-version=2021-10-01").value |
             Where-Object { $_.name -like "$Prefix-*" })
if (-not $aliases.Count) { Write-Host "No subscription alias starting with '$Prefix-'. Nothing to cancel." -ForegroundColor Green; return }

Write-Host "Subscriptions to cancel:" -ForegroundColor Yellow
foreach ($a in $aliases) {
    $subId = $a.properties.subscriptionId
    $groups = @()
    try { $groups = @((Arm GET "/subscriptions/$subId/resourcegroups?api-version=2021-04-01").value) } catch {}
    Write-Host ("  {0,-16} {1}  {2} resource group(s): {3}" -f $a.name, $subId, $groups.Count, (($groups | ForEach-Object name) -join ", "))
}
Write-Host "Every resource group in these subscriptions is deleted first." -ForegroundColor Yellow
if (-not $Force) {
    $answer = Read-Host "`nType CANCEL to continue"
    if ($answer -ne "CANCEL") { Write-Host "Stopped. Nothing was changed."; return }
}

foreach ($a in $aliases) {
    $subId = $a.properties.subscriptionId
    Write-Host "`n$($a.name) ($subId)" -ForegroundColor Cyan
    try {
        $diag = Invoke-AzRestMethod -Method GET -Path "/subscriptions/$subId/providers/Microsoft.Insights/diagnosticSettings/corlogging?api-version=2021-05-01-preview"
        if ($diag.StatusCode -eq 200) {
            Arm DELETE "/subscriptions/$subId/providers/Microsoft.Insights/diagnosticSettings/corlogging?api-version=2021-05-01-preview" | Out-Null
            Write-Host "  [OK]   removed the Activity log setting 'corlogging'" -ForegroundColor Green
        }
        $groups = @((Arm GET "/subscriptions/$subId/resourcegroups?api-version=2021-04-01").value)
        $jobs = foreach ($g in $groups) {
            Write-Host "  deleting resource group $($g.name) ..."
            Remove-AzResourceGroup -Id $g.id -Force -AsJob
        }
        if ($jobs) { $jobs | Wait-Job | Out-Null; $jobs | Remove-Job -Force }
        Arm POST "/subscriptions/$subId/providers/Microsoft.Subscription/cancel?api-version=2021-10-01" | Out-Null
        Write-Host "  [OK]   subscription cancelled" -ForegroundColor Green
        Arm DELETE "/providers/Microsoft.Subscription/aliases/$($a.name)?api-version=2021-10-01" | Out-Null
        Write-Host "  [OK]   alias removed" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
Write-Host "`nDone. Cancelled subscriptions are deleted by Microsoft after about 90 days." -ForegroundColor Cyan
