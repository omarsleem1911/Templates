<#
.SYNOPSIS
  Creates ~30 free test resources in 3 regions to try the cor. Azure onboarding portal.

.DESCRIPTION
  Run in Azure Cloud Shell (PowerShell). Per region it creates one resource group
  "cortest-<region>-rg" holding:
     2 x Network Security Group      free
     1 x Virtual Network             free
     2 x Storage Account (empty)     no fixed cost: billed only per GB stored / transactions
     1 x Key Vault (Standard)        no fixed cost: billed per operation
     1 x Automation Account (Free)   free (500 job minutes / month included)
     1 x App Service plan F1 + 1 Web App          free tier
     1 x Function App (Consumption, no App Insights)  free monthly grant
  Every resource group is tagged purpose=cor-portal-test; delete-test-resources.ps1 removes them.

  Nothing with an hourly price is created (no VMs, gateways, firewalls, public IPs, SQL, Cosmos DB).
  NOTE: the portal itself deploys Standard Event Hubs namespaces (one per region, about US$0.03/hour
  each) when you confirm a deployment: run delete-test-resources.ps1 -IncludeCorDeployment after testing.

.EXAMPLE
  ./create-test-resources.ps1
  ./create-test-resources.ps1 -Regions eastus,westeurope,northeurope -SubscriptionId <id>
#>
param(
    [string[]]$Regions = @("eastus", "westeurope", "uaenorth"),
    [string]$Prefix = "cortest",
    [string]$SubscriptionId
)

$ErrorActionPreference = "Stop"
if ($SubscriptionId) { Set-AzContext -Subscription $SubscriptionId | Out-Null }
$ctx = Get-AzContext
Write-Host "Subscription: $($ctx.Subscription.Name) ($($ctx.Subscription.Id))" -ForegroundColor Cyan
Write-Host "Regions     : $($Regions -join ', ')`n" -ForegroundColor Cyan

$tags = @{ purpose = "cor-portal-test"; createdBy = "create-test-resources.ps1" }
# Short random suffix: storage, key vault and app names must be unique across all of Azure.
$sfx = -join ((48..57) + (97..122) | Get-Random -Count 5 | ForEach-Object { [char]$_ })

foreach ($ns in "Microsoft.Network", "Microsoft.Storage", "Microsoft.KeyVault", "Microsoft.Automation", "Microsoft.Web") {
    if ((Get-AzResourceProvider -ProviderNamespace $ns).RegistrationState -contains "NotRegistered") {
        Write-Host "Registering $ns ..."
        Register-AzResourceProvider -ProviderNamespace $ns | Out-Null
    }
}

$ok = 0; $failed = @()
function Step([string]$label, [scriptblock]$action) {
    try {
        & $action | Out-Null
        Write-Host "  [OK]   $label" -ForegroundColor Green
        $script:ok++
    } catch {
        Write-Host "  [FAIL] $label - $($_.Exception.Message)" -ForegroundColor Yellow
        $script:failed += "$label - $($_.Exception.Message)"
    }
}

foreach ($r in $Regions) {
    $short = ($r -replace "[^a-z0-9]", "")
    $short = $short.Substring(0, [Math]::Min(6, $short.Length))
    $rg = "$Prefix-$r-rg"
    Write-Host "Region $r -> resource group $rg" -ForegroundColor Cyan
    try {
        New-AzResourceGroup -Name $rg -Location $r -Tag $tags -Force | Out-Null
    } catch {
        Write-Host "  [FAIL] resource group: $($_.Exception.Message) (skipping $r)" -ForegroundColor Red
        $failed += "$rg - $($_.Exception.Message)"
        continue
    }

    Step "NSG $Prefix-web-nsg-$r" {
        New-AzNetworkSecurityGroup -Name "$Prefix-web-nsg-$r" -ResourceGroupName $rg -Location $r -Tag $tags -Force }
    Step "NSG $Prefix-db-nsg-$r" {
        New-AzNetworkSecurityGroup -Name "$Prefix-db-nsg-$r" -ResourceGroupName $rg -Location $r -Tag $tags -Force }
    Step "VNet $Prefix-vnet-$r" {
        $subnet = New-AzVirtualNetworkSubnetConfig -Name "default" -AddressPrefix "10.10.1.0/24"
        New-AzVirtualNetwork -Name "$Prefix-vnet-$r" -ResourceGroupName $rg -Location $r -AddressPrefix "10.10.0.0/16" `
            -Subnet $subnet -Tag $tags -Force }

    $stLogs = "$Prefix$short$($sfx)l"
    $stFunc = "$Prefix$short$($sfx)f"
    foreach ($st in $stLogs, $stFunc) {
        Step "Storage $st" {
            New-AzStorageAccount -ResourceGroupName $rg -Name $st -Location $r -SkuName Standard_LRS -Kind StorageV2 `
                -AllowBlobPublicAccess $false -MinimumTlsVersion TLS1_2 -Tag $tags }
    }

    Step "Key Vault $Prefix-kv-$short-$sfx" {
        New-AzKeyVault -Name "$Prefix-kv-$short-$sfx" -ResourceGroupName $rg -Location $r -Sku Standard `
            -SoftDeleteRetentionInDays 7 -Tag $tags }
    Step "Automation $Prefix-auto-$r" {
        New-AzAutomationAccount -Name "$Prefix-auto-$r" -ResourceGroupName $rg -Location $r -Plan Free -Tags $tags }
    Step "App Service plan $Prefix-plan-$r (F1 Free)" {
        New-AzAppServicePlan -Name "$Prefix-plan-$r" -ResourceGroupName $rg -Location $r -Tier Free -Tag $tags }
    Step "Web App $Prefix-web-$short-$sfx" {
        New-AzWebApp -Name "$Prefix-web-$short-$sfx" -ResourceGroupName $rg -Location $r -AppServicePlan "$Prefix-plan-$r" }
    Step "Function App $Prefix-func-$short-$sfx (Consumption)" {
        New-AzFunctionApp -Name "$Prefix-func-$short-$sfx" -ResourceGroupName $rg -Location $r -StorageAccountName $stFunc `
            -Runtime PowerShell -RuntimeVersion 7.4 -FunctionsVersion 4 -OSType Windows -DisableApplicationInsights -Tag $tags }
}

Write-Host "`nCreated $ok resource(s)." -ForegroundColor Cyan
if ($failed.Count) {
    Write-Host "$($failed.Count) step(s) failed (often a region your subscription cannot use: rerun with -Regions):" -ForegroundColor Yellow
    $failed | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
}
Get-AzResourceGroup | Where-Object { $_.Tags -and $_.Tags["purpose"] -eq "cor-portal-test" } | ForEach-Object {
    Get-AzResource -ResourceGroupName $_.ResourceGroupName
} | Sort-Object Location, ResourceType | Format-Table Name, ResourceType, Location -AutoSize
Write-Host "When you are done testing: ./delete-test-resources.ps1 -IncludeCorDeployment" -ForegroundColor Cyan
