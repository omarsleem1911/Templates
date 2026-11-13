<#
.SYNOPSIS
  Creates 3 empty test subscriptions (to test Activity log onboarding in the cor. portal).

.DESCRIPTION
  Run in Azure Cloud Shell (PowerShell), signed in as the billing account owner.
  Uses the Subscription Alias API, which works for:
     * Microsoft Customer Agreement (MCA)   - includes new pay-as-you-go accounts
     * Enterprise Agreement (EA)            - needs an enrollment account (account owner)
  It does NOT work for legacy pay-as-you-go / free trial / Azure for Students accounts
  ("MicrosoftOnlineServicesProgram"): the script tells you and stops. Create those in the portal:
  Subscriptions -> + Add.

  An empty subscription costs nothing. In each new subscription the script registers
  Microsoft.Insights (needed for Activity log export) and creates one free resource group
  (cortest-activity-rg, tagged purpose=cor-portal-test) so the Activity log has events.

  Sign in to the cor. portal AFTER this finishes: the portal lists the subscriptions the admin
  can see at sign-in time.

.EXAMPLE
  ./create-test-subscriptions.ps1
  ./create-test-subscriptions.ps1 -Count 3 -Prefix cortest-sub -BillingScope "/providers/Microsoft.Billing/billingAccounts/.../invoiceSections/..."
#>
param(
    [int]$Count = 3,
    [string]$Prefix = "cortest-sub",
    [string]$BillingScope,
    [string]$Location = "eastus"
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

# --- 1. Find where new subscriptions are billed ------------------------------------------------
if (-not $BillingScope) {
    $accounts = @((Arm GET "/providers/Microsoft.Billing/billingAccounts?api-version=2020-05-01").value)
    if (-not $accounts.Count) { throw "This account can see no billing account. Sign in as the billing account owner." }
    Write-Host "Billing accounts:" -ForegroundColor Cyan
    $accounts | ForEach-Object { Write-Host "  $($_.properties.displayName)  [$($_.properties.agreementType)]" }

    $mca = $accounts | Where-Object { $_.properties.agreementType -eq "MicrosoftCustomerAgreement" } | Select-Object -First 1
    $ea = $accounts | Where-Object { $_.properties.agreementType -eq "EnterpriseAgreement" } | Select-Object -First 1
    if ($mca) {
        $profiles = @((Arm GET "$($mca.id)/billingProfiles?api-version=2020-05-01").value)
        foreach ($bp in $profiles) {
            $sections = @((Arm GET "$($bp.id)/invoiceSections?api-version=2020-05-01").value)
            if ($sections.Count) { $BillingScope = $sections[0].id; break }
        }
    } elseif ($ea) {
        $enrollments = @((Arm GET "$($ea.id)/enrollmentAccounts?api-version=2019-10-01-preview").value)
        if ($enrollments.Count) { $BillingScope = $enrollments[0].id }
    } else {
        Write-Host "`nThis is a legacy pay-as-you-go / free / student account: subscriptions cannot be created by script." -ForegroundColor Yellow
        Write-Host "Create them in the Azure portal instead: Subscriptions -> + Add -> Pay-As-You-Go (empty subscriptions cost nothing)." -ForegroundColor Yellow
        return
    }
    if (-not $BillingScope) { throw "No invoice section / enrollment account found under the billing account." }
}
Write-Host "Billing scope: $BillingScope`n" -ForegroundColor Cyan

# --- 2. Create the subscriptions ----------------------------------------------------------------
$tenant = (Get-AzContext).Tenant.Id
$created = @()
for ($i = 1; $i -le $Count; $i++) {
    $alias = "$Prefix-$i"
    Write-Host "Creating subscription '$alias' ..."
    $body = @{ properties = @{ displayName = $alias; billingScope = $BillingScope; workload = "Production"
                               additionalProperties = @{ subscriptionTenantId = $tenant
                                                         tags = @{ purpose = "cor-portal-test" } } } }
    try {
        $res = Arm PUT "/providers/Microsoft.Subscription/aliases/$($alias)?api-version=2021-10-01" $body
        $tries = 0
        while ($res.properties.provisioningState -notin "Succeeded", "Failed" -and $tries -lt 60) {
            Start-Sleep -Seconds 10; $tries++
            $res = Arm GET "/providers/Microsoft.Subscription/aliases/$($alias)?api-version=2021-10-01"
        }
        if ($res.properties.provisioningState -ne "Succeeded") { throw "provisioning state: $($res.properties.provisioningState)" }
        $subId = $res.properties.subscriptionId
        Write-Host "  [OK]   $alias -> $subId" -ForegroundColor Green
        $created += [pscustomobject]@{ Alias = $alias; SubscriptionId = $subId }
    } catch {
        Write-Host "  [FAIL] $alias - $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# --- 3. Prepare each subscription for Activity log export ----------------------------------------
Write-Host "`nWaiting 60 s for the new subscriptions to become usable..."
Start-Sleep -Seconds 60
foreach ($c in $created) {
    try {
        Arm POST "/subscriptions/$($c.SubscriptionId)/providers/Microsoft.Insights/register?api-version=2021-04-01" | Out-Null
        Arm PUT "/subscriptions/$($c.SubscriptionId)/resourcegroups/cortest-activity-rg?api-version=2021-04-01" @{
            location = $Location; tags = @{ purpose = "cor-portal-test" } } | Out-Null
        Write-Host "  [OK]   $($c.Alias): Microsoft.Insights registered, cortest-activity-rg created (Activity log has events)" -ForegroundColor Green
    } catch {
        Write-Host "  [WARN] $($c.Alias): $($_.Exception.Message) - rerun later or do it in the portal" -ForegroundColor Yellow
    }
}

Write-Host "`nCreated $($created.Count) of $Count subscription(s):" -ForegroundColor Cyan
$created | Format-Table -AutoSize
Write-Host "Now sign in to the cor. portal again so it sees them. Remove them later with ./cancel-test-subscriptions.ps1" -ForegroundColor Cyan
