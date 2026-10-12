<#
.SYNOPSIS
    Interactive entrypoint for PostgreSQL reference, Forge coverage, and Hiera/control-repo evidence scanning.
#>

[CmdletBinding()]
param(
    [string]$InventoryPath = ".\_forge_modules\inventory\forge_inventory.json",
    [string]$ReportsDir = ".\_forge_modules\reports",
    [string]$HieraPath = ".\hiera",
    [switch]$SkipHiera,
    [switch]$NonInteractive,
    [switch]$SummaryOnly,
    [switch]$VerboseFileErrors
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ModulePath = Join-Path $PSScriptRoot "ForgeModuleScan.psm1"

function Show-ScanMenu {
    Write-Host ""
    Write-Host "PostgreSQL Module Investigation"
    Write-Host "1. Run Forge module scan only"
    Write-Host "2. Run Forge module scan + Hiera/control-repo scan using default .\hiera"
    Write-Host "3. Run Forge module scan + Hiera/control-repo scan using custom path"
    Write-Host "4. Exit"
    Write-Host "5. Print latest summary report"
    Write-Host ""
}

function Show-LatestSummaryReport {
    param([string]$ReportsDir)

    $summaryPath = Join-Path $ReportsDir "postgresql_reference_summary.md"

    if (-not (Test-Path $summaryPath)) {
        throw "Summary report not found: $summaryPath. Run a scan first."
    }

    Get-Content $summaryPath
}

try {
    if (-not (Test-Path $ModulePath)) {
        throw "Required module not found: $ModulePath"
    }

    Import-Module $ModulePath -Force

    if ($SummaryOnly) {
        Show-LatestSummaryReport -ReportsDir $ReportsDir
        return
    }

    if (-not $NonInteractive) {
        Show-ScanMenu
        $choice = Read-Host "Select an option"

        switch ($choice) {
            "1" { $SkipHiera = $true }
            "2" { $SkipHiera = $false; $HieraPath = ".\hiera" }
            "3" { $SkipHiera = $false; $HieraPath = Read-Host "Enter Hiera/control-repo path" }
            "4" { Write-Host "Exiting."; return }
            "5" { Show-LatestSummaryReport -ReportsDir $ReportsDir; return }
            default { throw "Invalid menu option: $choice" }
        }
    }

    Write-ForgeScanSection "Preparing scan"

    if (-not (Test-Path $InventoryPath)) {
        throw "Inventory file not found: $InventoryPath. Run download_forge_modules.ps1 first."
    }

    New-Item -ItemType Directory -Force -Path $ReportsDir | Out-Null

    try {
        $inventory = Get-Content $InventoryPath -Raw | ConvertFrom-Json
    }
    catch {
        Write-Error "Failed to read or parse inventory file: $InventoryPath. $($_.Exception.Message)"
        throw
    }

    $modules = @($inventory.modules | Where-Object { $_.status -eq "ok" })

    Write-Host "Inventory: $InventoryPath"
    Write-Host "Modules to scan: $($modules.Count)"
    Write-Host "Reports dir: $ReportsDir"

    Write-ForgeScanSection "Collecting Forge validation coverage"
    $coverage = Get-ForgeCoverageMetadata -Modules $modules
    Write-Host "Validated modules: $(@($coverage.Values | Where-Object { $_.validated -eq $true }).Count)/$($modules.Count)"

    Write-ForgeScanSection "Scanning Forge modules"
    $scan = Invoke-PostgreSqlReferenceScan -Modules $modules -VerboseFileErrors:$VerboseFileErrors

    $hieraScan = $null

    if ($SkipHiera) {
        Write-ForgeScanSection "Skipping Hiera/control-repo scan"
    }
    else {
        Write-ForgeScanSection "Scanning Hiera/control-repo evidence"
        Write-Host "Hiera/control-repo path: $HieraPath"
        $hieraScan = Invoke-HieraEvidenceScan -HieraPath $HieraPath -VerboseFileErrors:$VerboseFileErrors
        Write-Host "Hiera scan status: $($hieraScan.status)"
        Write-Host "Hiera findings:    $(@($hieraScan.findings).Count)"
    }

    Write-ForgeScanSection "Writing reports"

    $paths = Write-PostgreSqlReferenceReports `
        -Results @($scan.results) `
        -Errors @($scan.errors) `
        -Terms @($scan.terms) `
        -InventoryPath $InventoryPath `
        -ReportsDir $ReportsDir `
        -ScannedModules $modules.Count `
        -HieraScan $hieraScan `
        -CoverageMetadata $coverage

    Write-ForgeScanSection "Complete"

    Write-Host "JSON report:      $($paths.jsonReportPath)"
    Write-Host "Markdown report:  $($paths.markdownReportPath)"
    Write-Host "Summary report:   $($paths.summaryReportPath)"
    Write-Host "Error report:     $($paths.errorReportPath)"

    if ($null -ne $hieraScan) {
        Write-Host "Hiera report:     $($paths.hieraReportPath)"
    }

    Write-Host "Scan errors:      $(@($scan.errors).Count)"

    $scan.results |
        Select-Object module, version, status, risk, confidence, review_category, match_count, evidence_summary,
            @{ Name = "validated"; Expression = { if ($coverage.ContainsKey($_.module)) { $coverage[$_.module].validated_status } else { "unknown" } } },
            @{ Name = "downloads"; Expression = { if ($coverage.ContainsKey($_.module)) { Format-NullableNumber $coverage[$_.module].downloads } else { "unknown" } } } |
        Sort-Object @{ Expression = { switch ($_.risk) { "high" { 1 } "medium" { 2 } "low" { 3 } "none" { 4 } default { 5 } } } }, module |
        Format-Table -AutoSize
}
catch {
    Write-Host ""
    Write-Host "===== FATAL ERROR =====" -ForegroundColor Red
    Write-Host "Message: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Type:    $($_.Exception.GetType().FullName)" -ForegroundColor Red

    if ($_.InvocationInfo) {
        Write-Host "Line:    $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
        Write-Host "Command: $($_.InvocationInfo.Line.Trim())" -ForegroundColor Red
    }

    throw
}
