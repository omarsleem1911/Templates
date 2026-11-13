<#
.SYNOPSIS
  Deletes the test resources made by create-test-resources.ps1 (and, optionally, what the
  cor. onboarding portal deployed during the test).

.DESCRIPTION
  Always: deletes every resource group tagged purpose=cor-portal-test and purges their Key Vaults
  (soft-deleted vaults would otherwise keep their names for 7 days).

  With -IncludeCorDeployment, also removes what the portal created, which is what costs money:
    * resource groups tagged cor-integration=eventhub (the portal's "cor-logging-rg": Event Hubs
      namespaces, the checkpoint storage account);
    * the "corlogging" Activity log diagnostic setting in every subscription you can see;
    * the "corlogging" Microsoft Entra ID diagnostic setting (needs Global / Security Administrator).
  Diagnostic settings on the deleted test resources go away with them.

  Lists everything first and asks for confirmation (skip with -Force).

.EXAMPLE
  ./delete-test-resources.ps1
  ./delete-test-resources.ps1 -IncludeCorDeployment
#>
param(
    [switch]$IncludeCorDeployment,
    [string]$SubscriptionId,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
if ($SubscriptionId) { Set-AzContext -Subscription $SubscriptionId | Out-Null }
$ctx = Get-AzContext
Write-Host "Subscription: $($ctx.Subscription.Name) ($($ctx.Subscription.Id))`n" -ForegroundColor Cyan

$groups = @(Get-AzResourceGroup | Where-Object { $_.Tags -and $_.Tags["purpose"] -eq "cor-portal-test" })
$corGroups = @()
if ($IncludeCorDeployment) {
    $corGroups = @(Get-AzResourceGroup | Where-Object { $_.Tags -and $_.Tags["cor-integration"] -eq "eventhub" })
}

if (-not $groups.Count -and -not $corGroups.Count -and -not $IncludeCorDeployment) {
    Write-Host "Nothing to delete: no resource group tagged purpose=cor-portal-test." -ForegroundColor Green
    return
}

Write-Host "Resource groups to delete:" -ForegroundColor Yellow
foreach ($g in $groups + $corGroups) {
    $n = @(Get-AzResource -ResourceGroupName $g.ResourceGroupName).Count
    $kind = if ($corGroups -contains $g) { "portal deployment" } else { "test resources" }
    Write-Host ("  {0,-34} {1,-14} {2,3} resource(s)  [{3}]" -f $g.ResourceGroupName, $g.Location, $n, $kind)
}
if ($IncludeCorDeployment) {
    Write-Host "Diagnostic settings named 'corlogging' to delete: Activity log (each subscription), Microsoft Entra ID." -ForegroundColor Yellow
}
if (-not $Force) {
    $answer = Read-Host "`nType DELETE to continue"
    if ($answer -ne "DELETE") { Write-Host "Cancelled. Nothing was deleted."; return }
}

# Key Vaults to purge after their resource group is gone.
$vaults = foreach ($g in $groups) {
    Get-AzKeyVault -ResourceGroupName $g.ResourceGroupName | Select-Object VaultName, Location
}

# Delete the resource groups in parallel.
$jobs = foreach ($g in $groups + $corGroups) {
    Write-Host "Deleting $($g.ResourceGroupName) ..."
    Remove-AzResourceGroup -Name $g.ResourceGroupName -Force -AsJob
}
if ($jobs) {
    Write-Host "Waiting for the deletions to finish (a few minutes)..."
    $jobs | Wait-Job | Out-Null
    foreach ($j in $jobs) {
        if ($j.State -eq "Completed") { Write-Host "  [OK]   $($j.Name)" -ForegroundColor Green }
        else { Write-Host "  [FAIL] $($j.Name): $($j.ChildJobs[0].JobStateInfo.Reason)" -ForegroundColor Yellow }
    }
    $jobs | Remove-Job -Force
}

foreach ($v in $vaults) {
    try {
        Remove-AzKeyVault -VaultName $v.VaultName -Location $v.Location -InRemovedState -Force | Out-Null
        Write-Host "  [OK]   purged Key Vault $($v.VaultName)" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] purge $($v.VaultName): $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

if ($IncludeCorDeployment) {
    foreach ($s in Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }) {
        $path = "/subscriptions/$($s.Id)/providers/Microsoft.Insights/diagnosticSettings/corlogging?api-version=2021-05-01-preview"
        $r = Invoke-AzRestMethod -Method GET -Path $path
        if ($r.StatusCode -eq 200) {
            $d = Invoke-AzRestMethod -Method DELETE -Path $path
            $state = if ($d.StatusCode -lt 300) { "[OK]  " } else { "[FAIL]" }
            Write-Host "  $state Activity log setting 'corlogging' in $($s.Name) (HTTP $($d.StatusCode))"
        }
    }
    $path = "/providers/microsoft.aadiam/diagnosticSettings/corlogging?api-version=2017-04-01"
    $r = Invoke-AzRestMethod -Method GET -Path $path
    if ($r.StatusCode -eq 200) {
        $d = Invoke-AzRestMethod -Method DELETE -Path $path
        $state = if ($d.StatusCode -lt 300) { "[OK]  " } else { "[FAIL]" }
        Write-Host "  $state Microsoft Entra ID setting 'corlogging' (HTTP $($d.StatusCode))"
    } elseif ($r.StatusCode -eq 403) {
        Write-Host "  [SKIP] Microsoft Entra ID setting: this account cannot read it (needs Global / Security Administrator)." -ForegroundColor Yellow
    }
}

Write-Host "`nDone." -ForegroundColor Cyan
