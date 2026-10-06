<#
.SYNOPSIS
    Downloads and extracts Puppet Forge modules listed in modules.yaml.

.DESCRIPTION
    Reads requested_modules from modules.yaml, queries the Puppet Forge API for each module,
    downloads the current release tarball, validates SHA256 when Forge provides it,
    extracts the module, and writes a local inventory file.

    Idempotent behavior:
      - Existing valid downloads are reused.
      - Existing extracted module versions are reused.
      - Changed or invalid downloads are replaced.
      - Inventory is regenerated each run.

.REQUIREMENTS
    PowerShell 5.1+
    tar available on PATH
    Internet access to forgeapi.puppet.com

.EXAMPLE
    .\scripts\download_forge_modules.ps1

.EXAMPLE
    .\scripts\download_forge_modules.ps1 -Force
#>

[CmdletBinding()]
param(
    [string]$ModulesFile = ".\modules.yaml",
    [string]$OutputRoot = ".\_forge_modules",
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Section {
    param([string]$Message)

    Write-Host ""
    Write-Host "===== $Message ====="
}

function Get-RequestedModules {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        throw "Modules file not found: $Path"
    }

    $modules = New-Object System.Collections.Generic.List[string]

    Get-Content $Path | ForEach-Object {
        $line = $_.Trim()

        if ($line -match "^-\s+") {
            $module = $line -replace "^-\s+", ""
            $module = $module.Trim()

            if (-not [string]::IsNullOrWhiteSpace($module)) {
                $modules.Add($module)
            }
        }
    }

    if ($modules.Count -eq 0) {
        throw "No modules found in $Path. Expected YAML list entries like: - puppet-nginx"
    }

    return $modules
}

function Convert-ForgeFileUriToUrl {
    param([string]$FileUri)

    if ([string]::IsNullOrWhiteSpace($FileUri)) {
        return $null
    }

    if ($FileUri.StartsWith("http")) {
        return $FileUri
    }

    return "https://forgeapi.puppet.com$FileUri"
}

function Test-FileSha256 {
    param(
        [string]$Path,
        [string]$ExpectedSha256
    )

    if (-not (Test-Path $Path)) {
        return $false
    }

    if ([string]::IsNullOrWhiteSpace($ExpectedSha256)) {
        return $true
    }

    $actual = (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
    return $actual -eq $ExpectedSha256.ToLowerInvariant()
}

function Get-SafeModuleDirectoryName {
    param(
        [string]$Module,
        [string]$Version
    )

    $safeModule = $Module -replace "[^a-zA-Z0-9_.-]", "_"
    $safeVersion = $Version -replace "[^a-zA-Z0-9_.-]", "_"

    return "$safeModule-$safeVersion"
}

function Invoke-ForgeModuleDownload {
    param(
        [string]$Module,
        [string]$DownloadDir,
        [string]$ExtractDir,
        [switch]$Force
    )

    $metadataUrl = "https://forgeapi.puppet.com/v3/modules/$Module"

    Write-Host "Querying Forge metadata: $Module"

    try {
        $response = Invoke-RestMethod -Uri $metadataUrl
    }
    catch {
        Write-Warning "Failed to query Forge for module: $Module"
        Write-Warning $_.Exception.Message

        return [pscustomobject][ordered]@{
            module        = $Module
            status        = "metadata_failed"
            version       = $null
            file_url      = $null
            download_path = $null
            extract_path  = $null
            sha256        = $null
            owner         = $null
            supported     = $null
            source        = $null
            dependencies  = @()
            tasks         = @()
            error         = $_.Exception.Message
        }
    }

    if (-not $response.current_release) {
        Write-Warning "No current_release found for module: $Module"

        return [pscustomobject][ordered]@{
            module        = $Module
            status        = "no_current_release"
            version       = $null
            file_url      = $null
            download_path = $null
            extract_path  = $null
            sha256        = $null
            owner         = $null
            supported     = $null
            source        = $null
            dependencies  = @()
            tasks         = @()
            error         = "No current_release in Forge response"
        }
    }

    $release = $response.current_release
    $version = [string]$release.version
    $fileUrl = Convert-ForgeFileUriToUrl -FileUri ([string]$release.file_uri)
    $sha256 = [string]$release.file_sha256

    if ([string]::IsNullOrWhiteSpace($fileUrl)) {
        Write-Warning "No file_uri found for module: $Module"

        return [pscustomobject][ordered]@{
            module        = $Module
            status        = "no_file_uri"
            version       = $version
            file_url      = $null
            download_path = $null
            extract_path  = $null
            sha256        = $sha256
            owner         = $null
            supported     = $null
            source        = $null
            dependencies  = @()
            tasks         = @()
            error         = "No file_uri in current_release"
        }
    }

    $safeName = Get-SafeModuleDirectoryName -Module $Module -Version $version
    $tarballPath = Join-Path $DownloadDir "$safeName.tar.gz"
    $moduleExtractPath = Join-Path $ExtractDir $safeName
    $markerPath = Join-Path $moduleExtractPath ".download_complete.json"

    $downloadNeeded = $true

    if ((Test-Path $tarballPath) -and (-not $Force)) {
        if (Test-FileSha256 -Path $tarballPath -ExpectedSha256 $sha256) {
            Write-Host "Download already exists and passed validation: $tarballPath"
            $downloadNeeded = $false
        }
        else {
            Write-Warning "Existing download failed SHA256 validation. Re-downloading: $tarballPath"
            Remove-Item $tarballPath -Force
        }
    }

    if ($downloadNeeded) {
        Write-Host "Downloading $Module $version"
        Write-Host "Source: $fileUrl"
        Invoke-WebRequest -Uri $fileUrl -OutFile $tarballPath

        if (-not (Test-FileSha256 -Path $tarballPath -ExpectedSha256 $sha256)) {
            throw "SHA256 validation failed for $Module after download."
        }
    }

    $extractNeeded = $true

    if ((Test-Path $markerPath) -and (-not $Force)) {
        Write-Host "Extraction already complete: $moduleExtractPath"
        $extractNeeded = $false
    }

    if ($extractNeeded) {
        if (Test-Path $moduleExtractPath) {
            Remove-Item $moduleExtractPath -Recurse -Force
        }

        New-Item -ItemType Directory -Force -Path $moduleExtractPath | Out-Null

        Write-Host "Extracting to: $moduleExtractPath"
        tar -xzf $tarballPath -C $moduleExtractPath

        $marker = [ordered]@{
            module       = $Module
            version      = $version
            downloadedAt = (Get-Date).ToString("o")
            fileUrl      = $fileUrl
            sha256       = $sha256
        }

        $marker | ConvertTo-Json -Depth 10 | Out-File -FilePath $markerPath -Encoding utf8
    }

    return [pscustomobject][ordered]@{
        module        = $Module
        status        = "ok"
        version       = $version
        file_url      = $fileUrl
        download_path = $tarballPath
        extract_path  = $moduleExtractPath
        sha256        = $sha256
        owner         = $response.current_release.module.owner.username
        supported     = $response.current_release.supported
        source        = $response.current_release.metadata.source
        dependencies  = $response.current_release.metadata.dependencies
        tasks         = $response.current_release.tasks
        error         = $null
    }
}

Write-Section "Preparing directories"

$DownloadDir = Join-Path $OutputRoot "downloads"
$ExtractDir = Join-Path $OutputRoot "extracted"
$InventoryDir = Join-Path $OutputRoot "inventory"
$InventoryPath = Join-Path $InventoryDir "forge_inventory.json"

New-Item -ItemType Directory -Force -Path $DownloadDir | Out-Null
New-Item -ItemType Directory -Force -Path $ExtractDir | Out-Null
New-Item -ItemType Directory -Force -Path $InventoryDir | Out-Null

Write-Host "Modules file: $ModulesFile"
Write-Host "Output root:  $OutputRoot"

Write-Section "Reading requested modules"

$modules = Get-RequestedModules -Path $ModulesFile
Write-Host "Found $($modules.Count) requested modules."

Write-Section "Downloading Forge modules"

$inventory = New-Object System.Collections.Generic.List[object]

foreach ($module in $modules) {
    Write-Section $module

    try {
        $result = Invoke-ForgeModuleDownload `
            -Module $module `
            -DownloadDir $DownloadDir `
            -ExtractDir $ExtractDir `
            -Force:$Force

        $inventory.Add($result)
    }
    catch {
        Write-Warning "Unhandled failure for module: $module"
        Write-Warning $_.Exception.Message

        $inventory.Add([pscustomobject][ordered]@{
            module        = $module
            status        = "failed"
            version       = $null
            file_url      = $null
            download_path = $null
            extract_path  = $null
            sha256        = $null
            owner         = $null
            supported     = $null
            source        = $null
            dependencies  = @()
            tasks         = @()
            error         = $_.Exception.Message
        })
    }
}

Write-Section "Writing inventory"

$summary = [ordered]@{
    generatedAt = (Get-Date).ToString("o")
    modulesFile = $ModulesFile
    outputRoot  = $OutputRoot
    total       = $inventory.Count
    succeeded   = @($inventory | Where-Object { $_.status -eq "ok" }).Count
    failed      = @($inventory | Where-Object { $_.status -ne "ok" }).Count
    modules     = $inventory
}

$summary | ConvertTo-Json -Depth 50 | Out-File -FilePath $InventoryPath -Encoding utf8

Write-Section "Complete"

Write-Host "Inventory written to: $InventoryPath"
Write-Host "Downloads stored in:  $DownloadDir"
Write-Host "Extracted modules in: $ExtractDir"

$summary.modules |
    Select-Object module, status, version, extract_path, error |
    Format-Table -AutoSize
