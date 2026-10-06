Set-StrictMode -Version Latest

function Write-ForgeScanSection {
    param(
        [string]$Message
    )

    Write-Host ""
    Write-Host "===== $Message ====="
}

function Escape-MarkdownCell {
    param(
        [AllowNull()][object]$Value
    )

    if ($null -eq $Value) {
        return ""
    }

    $text = [string]$Value

    if ([string]::IsNullOrWhiteSpace($text)) {
        return ""
    }

    $text = $text -replace "\|", "\\|"
    $text = $text -replace "`r?`n", " "

    return $text
}

function Format-NullableNumber {
    param(
        [AllowNull()][object]$Value
    )

    if ($null -eq $Value) {
        return "unknown"
    }

    try {
        return ([int64]$Value).ToString("N0")
    }
    catch {
        return [string]$Value
    }
}

function Get-PostgreSqlScanTerms {
    return @(
        "postgresql",
        "postgres",
        "pgsql",
        "pg_",
        "pgbouncer",
        "pgpass",
        "postgres_exporter",
        "geo_postgresql",
        "5432",
        "database",
        "db_host",
        "db_port",
        "db_user",
        "db_password",
        "store_git_keys_in_db",
        "ompgsql",
        "pg_hba"
    )
}

function Get-ForgeScanFileExtensions {
    return @(
        ".pp",
        ".erb",
        ".epp",
        ".yaml",
        ".yml",
        ".json",
        ".md",
        ".sh",
        ".rb",
        ".conf",
        ".txt"
    )
}

function Get-HieraScanFileExtensions {
    return @(
        ".yaml",
        ".yml",
        ".json",
        ".pp"
    )
}

function Get-FindingArea {
    param(
        [AllowNull()][string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return "unknown"
    }

    $normalized = $Path.Replace("\", "/").ToLowerInvariant()

    if ($normalized -match "/spec/|/test/|/tests/|/fixtures/|/acceptance/") {
        return "test"
    }

    if ($normalized -match "/readme|/changelog|/reference|\.md$|/docs/|/documentation/") {
        return "documentation"
    }

    if ($normalized -match "/manifests/|/templates/|/tasks/|/plans/|/files/|/lib/") {
        return "source"
    }

    if ($normalized -match "/data/") {
        return "data"
    }

    if ($normalized -match "\.pp$") {
        return "source"
    }

    if ($normalized -match "\.ya?ml$|\.json$") {
        return "data"
    }

    return "other"
}

function Get-FindingEvidence {
    param(
        [AllowNull()][string]$Line,
        [AllowNull()][string]$Path
    )

    $lineText = ""

    if ($null -ne $Line) {
        $lineText = $Line.ToLowerInvariant()
    }

    $area = Get-FindingArea -Path $Path

    $postgresTerms = @(
        "postgresql",
        "postgres",
        "pgbouncer",
        "pgpass",
        "postgres_exporter",
        "geo_postgresql",
        "store_git_keys_in_db",
        "ompgsql",
        "pg_hba"
    )

    foreach ($term in $postgresTerms) {
        if ($lineText.Contains($term)) {
            if ($area -eq "source" -or $area -eq "data") {
                return "source-postgresql"
            }

            return "reference-postgresql"
        }
    }

    if ($lineText.Contains("database") -or $lineText.Contains("db_")) {
        return "generic-database"
    }

    if ($lineText.Contains("pg_") -or $lineText.Contains("5432")) {
        return "weak-token"
    }

    return "unknown"
}

function Get-RiskLevel {
    param(
        [int]$SourcePostgreSqlMatches,
        [int]$ReferencePostgreSqlMatches,
        [int]$GenericDatabaseMatches,
        [int]$WeakTokenMatches
    )

    if ($SourcePostgreSqlMatches -ge 5) {
        return "high"
    }

    if ($SourcePostgreSqlMatches -gt 0) {
        return "medium"
    }

    if ($ReferencePostgreSqlMatches -ge 5) {
        return "medium"
    }

    if (($ReferencePostgreSqlMatches + $GenericDatabaseMatches) -gt 0) {
        return "low"
    }

    if ($WeakTokenMatches -gt 0) {
        return "low"
    }

    return "none"
}

function Get-EvidenceSummary {
    param(
        [int]$SourcePostgreSqlMatches,
        [int]$ReferencePostgreSqlMatches,
        [int]$GenericDatabaseMatches,
        [int]$WeakTokenMatches
    )

    $parts = @()

    if ($SourcePostgreSqlMatches -gt 0) {
        $parts += "source PostgreSQL=$SourcePostgreSqlMatches"
    }

    if ($ReferencePostgreSqlMatches -gt 0) {
        $parts += "docs/tests PostgreSQL=$ReferencePostgreSqlMatches"
    }

    if ($GenericDatabaseMatches -gt 0) {
        $parts += "generic database=$GenericDatabaseMatches"
    }

    if ($WeakTokenMatches -gt 0) {
        $parts += "weak token=$WeakTokenMatches"
    }

    if ($parts.Count -eq 0) {
        return "none"
    }

    return ($parts -join "; ")
}

function Get-ReviewCategory {
    param(
        [string]$Module,
        [object[]]$Findings,
        [object[]]$MatchedTerms
    )

    $moduleLower = $Module.ToLowerInvariant()
    $terms = @($MatchedTerms | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $paths = @($Findings | ForEach-Object { ([string]$_.path).Replace("\", "/").ToLowerInvariant() })

    if ($moduleLower -eq "puppet-gitlab") {
        return "direct-postgresql-management"
    }

    if ($moduleLower -eq "puppet-nftables" -or ($paths -match "rules/out/postgres")) {
        return "postgresql-connectivity"
    }

    if ($moduleLower -eq "puppet-augeasproviders_core" -or ($terms -contains "pg_hba")) {
        return "postgresql-access-config"
    }

    if ($moduleLower -eq "puppet-rsyslog" -or ($terms -contains "ompgsql")) {
        return "postgresql-output-plugin"
    }

    if (($terms -contains "postgres") -or ($terms -contains "postgresql") -or ($terms -contains "pgbouncer")) {
        return "postgresql-related-capability"
    }

    if (($terms -contains "database") -or ($terms -contains "db_password")) {
        return "generic-database-only"
    }

    if (($terms -contains "pg_") -or ($terms -contains "5432")) {
        return "weak-token-only"
    }

    return "no-evidence"
}

function Get-Confidence {
    param(
        [string]$ReviewCategory,
        [int]$SourcePostgreSqlMatches,
        [int]$ReferencePostgreSqlMatches,
        [int]$GenericDatabaseMatches,
        [int]$WeakTokenMatches
    )

    if ($ReviewCategory -eq "direct-postgresql-management" -and $SourcePostgreSqlMatches -gt 0) {
        return "confirmed-capability"
    }

    if ($ReviewCategory -in @("postgresql-connectivity", "postgresql-output-plugin", "postgresql-access-config")) {
        return "conditional"
    }

    if ($SourcePostgreSqlMatches -gt 0) {
        return "likely"
    }

    if ($ReferencePostgreSqlMatches -gt 0) {
        return "contextual"
    }

    if (($GenericDatabaseMatches + $WeakTokenMatches) -gt 0) {
        return "weak"
    }

    return "none"
}

function Get-CustomerValidationQuestions {
    param(
        [string]$ReviewCategory
    )

    switch ($ReviewCategory) {
        "direct-postgresql-management" {
            return @(
                "Are any GitLab PostgreSQL-related Hiera keys set, such as gitlab::postgresql, gitlab::geo_postgresql, gitlab::pgbouncer, gitlab::postgres_exporter, gitlab::pgbouncer_exporter, gitlab::pgpass_file_ensure, or gitlab::store_git_keys_in_db?",
                "Is the module used to render /etc/gitlab/gitlab.rb PostgreSQL, Geo PostgreSQL, PgBouncer, or exporter settings?",
                "Are the postgres_upgrade or post_upgrade tasks used operationally?"
            )
        }
        "postgresql-connectivity" {
            return @(
                "Is the PostgreSQL connectivity class or rule included anywhere, and does PostgreSQL still use TCP port 5432 after the upgrade?"
            )
        }
        "postgresql-access-config" {
            return @(
                "Does the control repo use this module/provider to manage pg_hba.conf or other PostgreSQL access-control files?"
            )
        }
        "postgresql-output-plugin" {
            return @(
                "Is rsyslog configured to use the ompgsql PostgreSQL output module or send logs to a PostgreSQL database?"
            )
        }
        default {
            return @()
        }
    }
}

function New-ScanErrorObject {
    param(
        [string]$Module,
        [string]$Version,
        [string]$Operation,
        [AllowNull()][string]$Path,
        [System.Management.Automation.ErrorRecord]$ErrorRecord
    )

    $scriptLine = $null
    $command = $null

    if ($ErrorRecord.InvocationInfo) {
        $scriptLine = $ErrorRecord.InvocationInfo.ScriptLineNumber
        $command = $ErrorRecord.InvocationInfo.Line

        if ($command) {
            $command = $command.Trim()
        }
    }

    return [pscustomobject][ordered]@{
        module      = $Module
        version     = $Version
        operation   = $Operation
        path        = $Path
        error_type  = $ErrorRecord.Exception.GetType().FullName
        message     = $ErrorRecord.Exception.Message
        script_line = $scriptLine
        command     = $command
    }
}

function Invoke-PostgreSqlReferenceScan {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Modules,
        [switch]$VerboseFileErrors
    )

    $terms = Get-PostgreSqlScanTerms
    $fileExtensions = Get-ForgeScanFileExtensions
    $results = @()
    $scanErrors = @()

    foreach ($module in $Modules) {
        $moduleName = [string]$module.module
        $moduleVersion = [string]$module.version
        $extractPath = [string]$module.extract_path

        Write-Host "Scanning $moduleName $moduleVersion"

        try {
            if (-not (Test-Path $extractPath)) {
                $results += [pscustomobject][ordered]@{
                    module                        = $moduleName
                    version                       = $moduleVersion
                    status                        = "extract_path_missing"
                    risk                          = "unknown"
                    match_count                   = 0
                    source_postgresql_matches     = 0
                    reference_postgresql_matches  = 0
                    generic_database_matches      = 0
                    weak_token_matches            = 0
                    evidence_summary              = "extract path missing"
                    review_category               = "unknown"
                    confidence                    = "none"
                    matched_terms                 = @()
                    findings                      = @()
                    customer_validation_questions = @()
                }

                continue
            }

            $findings = @()
            $matchedTerms = @()

            try {
                $files = @(Get-ChildItem $extractPath -Recurse -File -ErrorAction Stop | Where-Object {
                    $fileExtensions -contains $_.Extension.ToLowerInvariant()
                })
            }
            catch {
                $scanErrors += New-ScanErrorObject -Module $moduleName -Version $moduleVersion -Operation "enumerate_files" -Path $extractPath -ErrorRecord $_
                $files = @()
            }

            foreach ($file in $files) {
                try {
                    $matches = @(Select-String -Path $file.FullName -Pattern $terms -SimpleMatch -ErrorAction Stop)
                }
                catch {
                    $scanErrors += New-ScanErrorObject -Module $moduleName -Version $moduleVersion -Operation "select_string" -Path $file.FullName -ErrorRecord $_

                    if ($VerboseFileErrors) {
                        Write-Warning "$moduleName failed file scan: $($file.FullName)"
                    }

                    continue
                }

                foreach ($match in $matches) {
                    $lineTextRaw = [string]$match.Line
                    $lowerLine = $lineTextRaw.ToLowerInvariant()

                    foreach ($term in $terms) {
                        $lowerTerm = $term.ToLowerInvariant()

                        if ($lowerLine.Contains($lowerTerm) -and -not ($matchedTerms -contains $lowerTerm)) {
                            $matchedTerms += $lowerTerm
                        }
                    }

                    try {
                        $relativePath = Resolve-Path -Path $file.FullName -Relative -ErrorAction Stop
                    }
                    catch {
                        $relativePath = $file.FullName
                    }

                    $area = Get-FindingArea -Path $relativePath
                    $evidence = Get-FindingEvidence -Line $lineTextRaw -Path $relativePath

                    $findings += [pscustomobject][ordered]@{
                        path        = $relativePath
                        area        = $area
                        evidence    = $evidence
                        line_number = $match.LineNumber
                        line        = $lineTextRaw.Trim()
                    }
                }
            }

            $matchedTermsArray = @($matchedTerms | Sort-Object -Unique)
            $sourcePostgreSqlMatches = @($findings | Where-Object { $_.evidence -eq "source-postgresql" }).Count
            $referencePostgreSqlMatches = @($findings | Where-Object { $_.evidence -eq "reference-postgresql" }).Count
            $genericDatabaseMatches = @($findings | Where-Object { $_.evidence -eq "generic-database" }).Count
            $weakTokenMatches = @($findings | Where-Object { $_.evidence -eq "weak-token" }).Count
            $risk = Get-RiskLevel -SourcePostgreSqlMatches $sourcePostgreSqlMatches -ReferencePostgreSqlMatches $referencePostgreSqlMatches -GenericDatabaseMatches $genericDatabaseMatches -WeakTokenMatches $weakTokenMatches
            $reviewCategory = Get-ReviewCategory -Module $moduleName -Findings $findings -MatchedTerms $matchedTermsArray
            $confidence = Get-Confidence -ReviewCategory $reviewCategory -SourcePostgreSqlMatches $sourcePostgreSqlMatches -ReferencePostgreSqlMatches $referencePostgreSqlMatches -GenericDatabaseMatches $genericDatabaseMatches -WeakTokenMatches $weakTokenMatches
            $evidenceSummary = Get-EvidenceSummary -SourcePostgreSqlMatches $sourcePostgreSqlMatches -ReferencePostgreSqlMatches $referencePostgreSqlMatches -GenericDatabaseMatches $genericDatabaseMatches -WeakTokenMatches $weakTokenMatches
            $questions = Get-CustomerValidationQuestions -ReviewCategory $reviewCategory

            $results += [pscustomobject][ordered]@{
                module                        = $moduleName
                version                       = $moduleVersion
                status                        = "ok"
                risk                          = $risk
                match_count                   = $findings.Count
                source_postgresql_matches     = $sourcePostgreSqlMatches
                reference_postgresql_matches  = $referencePostgreSqlMatches
                generic_database_matches      = $genericDatabaseMatches
                weak_token_matches            = $weakTokenMatches
                evidence_summary              = $evidenceSummary
                review_category               = $reviewCategory
                confidence                    = $confidence
                matched_terms                 = $matchedTermsArray
                findings                      = @($findings)
                customer_validation_questions = @($questions)
            }
        }
        catch {
            $scanErrors += New-ScanErrorObject -Module $moduleName -Version $moduleVersion -Operation "module_scan" -Path $extractPath -ErrorRecord $_
        }
    }

    return [pscustomobject][ordered]@{
        results = $results
        errors  = $scanErrors
        terms   = $terms
    }
}

function Get-HieraScanPatterns {
    return @(
        "gitlab::postgresql",
        "gitlab::geo_postgresql",
        "gitlab::pgbouncer",
        "gitlab::postgres_exporter",
        "gitlab::pgbouncer_exporter",
        "gitlab::pgpass_file_ensure",
        "gitlab::pgpass_file_location",
        "gitlab::pgbouncer_password",
        "gitlab::store_git_keys_in_db",
        "nftables::rules::out::postgres",
        "ompgsql",
        "rsyslog::actions::outputs::ompgsql",
        "pg_hba",
        "postgresql",
        "pgbouncer",
        "pgpass"
    )
}

function Get-HieraModuleHint {
    param(
        [string]$Line
    )

    $lower = $Line.ToLowerInvariant()

    if ($lower.Contains("gitlab::") -or $lower.Contains("include gitlab") -or $lower.Contains("class { 'gitlab") -or $lower.Contains('class { "gitlab')) {
        return "puppet-gitlab"
    }

    if ($lower.Contains("nftables::rules::out::postgres")) {
        return "puppet-nftables"
    }

    if ($lower.Contains("rsyslog") -or $lower.Contains("ompgsql")) {
        return "puppet-rsyslog"
    }

    if ($lower.Contains("pg_hba") -or $lower.Contains("augeasproviders")) {
        return "puppet-augeasproviders_core"
    }

    return "unknown"
}

function Get-HieraFindingType {
    param(
        [string]$Line
    )

    $trimmed = $Line.Trim()

    if ($trimmed -match '^["'']?[A-Za-z0-9_:.-]+["'']?\s*:') {
        return "hiera-key"
    }

    if ($trimmed -match "lookup\s*\(") {
        return "puppet-lookup"
    }

    if ($trimmed -match "class\s*\{|include\s+") {
        return "puppet-class-reference"
    }

    return "text-reference"
}

function Invoke-HieraEvidenceScan {
    param(
        [string]$HieraPath,
        [switch]$VerboseFileErrors
    )

    $patterns = Get-HieraScanPatterns
    $extensions = Get-HieraScanFileExtensions
    $findings = @()
    $errors = @()

    if ([string]::IsNullOrWhiteSpace($HieraPath)) {
        return [pscustomobject][ordered]@{
            status   = "not_requested"
            path     = $HieraPath
            findings = @()
            errors   = @()
            patterns = $patterns
        }
    }

    if (-not (Test-Path $HieraPath)) {
        return [pscustomobject][ordered]@{
            status   = "path_missing"
            path     = $HieraPath
            findings = @()
            errors   = @()
            patterns = $patterns
        }
    }

    $files = @(Get-ChildItem $HieraPath -Recurse -File -ErrorAction Stop | Where-Object {
        $extensions -contains $_.Extension.ToLowerInvariant()
    })

    foreach ($file in $files) {
        try {
            $matches = @(Select-String -Path $file.FullName -Pattern $patterns -SimpleMatch -ErrorAction Stop)
        }
        catch {
            $errors += New-ScanErrorObject -Module "hiera" -Version "n/a" -Operation "hiera_select_string" -Path $file.FullName -ErrorRecord $_
            continue
        }

        foreach ($match in $matches) {
            $lineText = [string]$match.Line
            $matched = @()

            foreach ($pattern in $patterns) {
                if ($lineText.ToLowerInvariant().Contains($pattern.ToLowerInvariant())) {
                    $matched += $pattern
                }
            }

            try {
                $relativePath = Resolve-Path -Path $file.FullName -Relative -ErrorAction Stop
            }
            catch {
                $relativePath = $file.FullName
            }

            $findings += [pscustomobject][ordered]@{
                path             = $relativePath
                line_number      = $match.LineNumber
                finding_type     = Get-HieraFindingType -Line $lineText
                module_hint      = Get-HieraModuleHint -Line $lineText
                matched_patterns = @($matched | Sort-Object -Unique)
                line             = $lineText.Trim()
            }
        }
    }

    return [pscustomobject][ordered]@{
        status   = "ok"
        path     = $HieraPath
        findings = @($findings)
        errors   = @($errors)
        patterns = $patterns
    }
}

function Get-ForgeCoverageMetadata {
    param(
        [object[]]$Modules
    )

    $coverage = @{}
    $validatedMap = @{}

    try {
        $validatedUrl = "https://forgeapi.puppet.com/v3/modules?endorsements=validated&limit=100&fields=slug,downloads,current_release"
        $validatedResponse = Invoke-RestMethod -Uri $validatedUrl -ErrorAction Stop

        foreach ($item in @($validatedResponse.results)) {
            $validatedMap[[string]$item.slug] = $item
        }
    }
    catch {
        Write-Warning "Could not retrieve Forge validated coverage metadata: $($_.Exception.Message)"
    }

    foreach ($module in $Modules) {
        $name = [string]$module.module
        $validated = $false
        $downloads = $null
        $forgeVersion = [string]$module.version

        if ($validatedMap.ContainsKey($name)) {
            $validated = $true
            $downloads = $validatedMap[$name].downloads

            if ($validatedMap[$name].current_release -and $validatedMap[$name].current_release.version) {
                $forgeVersion = [string]$validatedMap[$name].current_release.version
            }
        }
        else {
            try {
                $response = Invoke-RestMethod -Uri "https://forgeapi.puppet.com/v3/modules/$name" -ErrorAction Stop

                if ($response.downloads) {
                    $downloads = $response.downloads
                }
                elseif ($response.current_release -and $response.current_release.downloads) {
                    $downloads = $response.current_release.downloads
                }

                if ($response.current_release -and $response.current_release.version) {
                    $forgeVersion = [string]$response.current_release.version
                }
            }
            catch {
                # Leave downloads/version as inventory-derived values.
            }
        }

        $dependencyCount = 0
        $taskCount = 0

        if ($module.dependencies) {
            $dependencyCount = @($module.dependencies).Count
        }

        if ($module.tasks) {
            $taskCount = @($module.tasks).Count
        }

        $coverage[$name] = [pscustomobject][ordered]@{
            module           = $name
            validated        = $validated
            validated_status = $(if ($validated) { "validated" } else { "not validated" })
            downloads        = $downloads
            forge_version    = $forgeVersion
            supported        = $module.supported
            source           = $module.source
            dependency_count = $dependencyCount
            task_count       = $taskCount
        }
    }

    return $coverage
}

function Get-HieraEvidenceForModule {
    param(
        [string]$Module,
        [object[]]$HieraFindings
    )

    return @($HieraFindings | Where-Object {
        $_.module_hint -eq $Module -or
        ($Module -eq "puppet-gitlab" -and $_.line.ToLowerInvariant().Contains("gitlab"))
    })
}

function Write-PostgreSqlReferenceReports {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Results,
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [object[]]$Errors = @(),
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Terms,
        [Parameter(Mandatory = $true)]
        [string]$InventoryPath,
        [Parameter(Mandatory = $true)]
        [string]$ReportsDir,
        [Parameter(Mandatory = $true)]
        [int]$ScannedModules,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$HieraScan = $null,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [hashtable]$CoverageMetadata = $null
    )

    New-Item -ItemType Directory -Force -Path $ReportsDir | Out-Null

    $jsonReportPath = Join-Path $ReportsDir "postgresql_reference_report.json"
    $markdownReportPath = Join-Path $ReportsDir "postgresql_reference_report.md"
    $summaryReportPath = Join-Path $ReportsDir "postgresql_reference_summary.md"
    $errorReportPath = Join-Path $ReportsDir "postgresql_reference_errors.json"
    $hieraReportPath = Join-Path $ReportsDir "hiera_postgresql_evidence.json"

    $hieraFindings = @()
    $hieraErrors = @()
    $hieraStatus = "not_analyzed"
    $hieraPath = $null

    if ($null -ne $HieraScan) {
        $hieraStatus = [string]$HieraScan.status
        $hieraPath = [string]$HieraScan.path
        $hieraFindings = @($HieraScan.findings)
        $hieraErrors = @($HieraScan.errors)
    }

    $allErrors = @($Errors) + @($hieraErrors)

    if ($null -eq $CoverageMetadata) {
        $CoverageMetadata = @{}
    }

    $validatedCount = @($CoverageMetadata.Values | Where-Object { $_.validated -eq $true }).Count
    $notValidatedCount = @($CoverageMetadata.Values | Where-Object { $_.validated -ne $true }).Count

    $sortedResults = $Results | Sort-Object @{ Expression = { switch ($_.risk) { "high" { 1 } "medium" { 2 } "low" { 3 } "none" { 4 } default { 5 } } } }, module

    $report = [ordered]@{
        generatedAt    = (Get-Date).ToString("o")
        inventoryPath  = $InventoryPath
        scannedModules = $ScannedModules
        forgeCoverage  = @{
            validated     = $validatedCount
            not_validated = $notValidatedCount
            modules       = $CoverageMetadata.Values
        }
        terms          = $Terms
        results        = $Results
        hiera          = $HieraScan
        errors         = $allErrors
    }

    $report | ConvertTo-Json -Depth 60 | Out-File -FilePath $jsonReportPath -Encoding utf8
    @($allErrors) | ConvertTo-Json -Depth 20 | Out-File -FilePath $errorReportPath -Encoding utf8

    if ($null -ne $HieraScan) {
        $HieraScan | ConvertTo-Json -Depth 40 | Out-File -FilePath $hieraReportPath -Encoding utf8
    }

    $today = (Get-Date).ToString("yyyy-MM-dd")

    $lines = @()
    $lines += "# PostgreSQL Reference Scan"
    $lines += ""
    $lines += "_Last updated: ${today}_"
    $lines += ""
    $lines += "This report combines Forge validation coverage, PostgreSQL source/reference evidence, and optional Hiera/control-repo evidence."
    $lines += ""
    $lines += "## Forge Coverage"
    $lines += ""
    $lines += "- Forge modules scanned: $ScannedModules"
    $lines += "- Validated modules: $validatedCount"
    $lines += "- Not validated modules: $notValidatedCount"
    $lines += ""
    $lines += "## Hiera / Control Repo Evidence"
    $lines += ""
    $lines += "Hiera scan status: **$hieraStatus**"
    $lines += ""
    $lines += "Hiera/control-repo findings: $($hieraFindings.Count)"
    $lines += ""
    $lines += "## How Evidence Is Classified"
    $lines += ""
    $lines += "- **source-postgresql**: PostgreSQL-specific term in module source, data, templates, tasks, files, or library code."
    $lines += "- **reference-postgresql**: PostgreSQL-specific term in docs, changelogs, references, tests, fixtures, or examples."
    $lines += "- **generic-database**: Generic database term without PostgreSQL-specific evidence."
    $lines += "- **weak-token**: Weak indicators such as pg_ or 5432."
    $lines += ""
    $lines += "## Summary"
    $lines += ""
    $lines += "| Module | Version | Validated | Downloads | Risk | Confidence | Review Category | Matches | Evidence Summary | Hiera Evidence |"
    $lines += "|--------|---------|-----------|-----------|------|------------|-----------------|---------|------------------|----------------|"

    foreach ($item in $sortedResults) {
        $cov = $CoverageMetadata[$item.module]
        $validated = if ($cov) { $cov.validated_status } else { "unknown" }
        $downloads = if ($cov) { Format-NullableNumber $cov.downloads } else { "unknown" }
        $moduleHiera = Get-HieraEvidenceForModule -Module $item.module -HieraFindings $hieraFindings
        $hieraEvidence = if ($hieraStatus -eq "ok") { if (@($moduleHiera).Count -gt 0) { "found=$(@($moduleHiera).Count)" } else { "not found" } } else { $hieraStatus }

        $lines += "| $(Escape-MarkdownCell $item.module) | $(Escape-MarkdownCell $item.version) | $(Escape-MarkdownCell $validated) | $(Escape-MarkdownCell $downloads) | $(Escape-MarkdownCell $item.risk) | $(Escape-MarkdownCell $item.confidence) | $(Escape-MarkdownCell $item.review_category) | $($item.match_count) | $(Escape-MarkdownCell $item.evidence_summary) | $(Escape-MarkdownCell $hieraEvidence) |"
    }

    $lines += ""
    $lines += "## Follow-up Questions"
    $lines += ""

    foreach ($item in ($sortedResults | Where-Object { $_.customer_validation_questions.Count -gt 0 })) {
        $lines += "### $($item.module)"
        $lines += ""

        foreach ($q in $item.customer_validation_questions) {
            $lines += "- $q"
        }

        $lines += ""
    }

    $lines += "## Findings by Module"
    $lines += ""

    foreach ($item in ($sortedResults | Where-Object { $_.match_count -gt 0 })) {
        $lines += "### $($item.module) $($item.version)"
        $lines += ""
        $lines += "Risk: **$($item.risk)**"
        $lines += ""
        $lines += "Confidence: **$($item.confidence)**"
        $lines += ""
        $lines += "Review category: **$($item.review_category)**"
        $lines += ""
        $lines += "Evidence summary: $($item.evidence_summary)"
        $lines += ""
        $lines += "| Area | Evidence | File | Line | Text |"
        $lines += "|------|----------|------|------|------|"

        $sortedFindings = $item.findings | Sort-Object @{ Expression = { switch ($_.evidence) { "source-postgresql" { 1 } "reference-postgresql" { 2 } "generic-database" { 3 } "weak-token" { 4 } default { 5 } } } }, path, line_number

        foreach ($finding in $sortedFindings) {
            $lineText = [string]$finding.line

            if ($lineText.Length -gt 240) {
                $lineText = $lineText.Substring(0, 240) + "..."
            }

            $lines += "| $(Escape-MarkdownCell $finding.area) | $(Escape-MarkdownCell $finding.evidence) | $(Escape-MarkdownCell $finding.path) | $($finding.line_number) | ``$(Escape-MarkdownCell $lineText)`` |"
        }

        $lines += ""
    }

    if (@($allErrors).Count -gt 0) {
        $lines += "## Scan Errors"
        $lines += ""
        $lines += "Some files or modules could not be scanned. See ``$errorReportPath`` for full details."
    }

    $lines | Out-File -FilePath $markdownReportPath -Encoding utf8

    $reviewItems = @($sortedResults | Where-Object { $_.risk -ne "none" -and $_.review_category -notin @("weak-token-only", "generic-database-only") })
    $primaryItems = @($sortedResults | Where-Object { $_.risk -eq "high" -or $_.review_category -eq "direct-postgresql-management" })
    $conditionalItems = @($sortedResults | Where-Object { $_.review_category -in @("postgresql-connectivity", "postgresql-access-config", "postgresql-output-plugin", "postgresql-related-capability") })
    $weakItems = @($sortedResults | Where-Object { $_.review_category -in @("generic-database-only", "weak-token-only") })
    $noEvidenceItems = @($sortedResults | Where-Object { $_.review_category -eq "no-evidence" })

    $summaryLines = @()
    $summaryLines += "# PostgreSQL Investigation Summary"
    $summaryLines += ""
    $summaryLines += "_Last updated: ${today}_"
    $summaryLines += ""
    $summaryLines += "## Result"
    $summaryLines += ""
    $summaryLines += "- Forge modules scanned: $ScannedModules"
    $summaryLines += "- Forge validated coverage: $validatedCount/$ScannedModules"
    $summaryLines += "- Hiera/control-repo scan: $hieraStatus"
    $summaryLines += "- Hiera/control-repo findings: $($hieraFindings.Count)"
    $summaryLines += "- Scan errors: $(@($allErrors).Count)"
    $summaryLines += ""
    $summaryLines += "## Modules Requiring Review"
    $summaryLines += ""
    $summaryLines += "| Module | Version | Validated | Downloads | Risk | Confidence | Category | Evidence | Hiera Evidence |"
    $summaryLines += "|--------|---------|-----------|-----------|------|------------|----------|----------|----------------|"

    if ($reviewItems.Count -eq 0) {
        $summaryLines += "| None | | | | none | none | no-evidence | No PostgreSQL-relevant module findings require review. | |"
    }
    else {
        foreach ($item in $reviewItems) {
            $cov = $CoverageMetadata[$item.module]
            $validated = if ($cov) { $cov.validated_status } else { "unknown" }
            $downloads = if ($cov) { Format-NullableNumber $cov.downloads } else { "unknown" }
            $moduleHiera = Get-HieraEvidenceForModule -Module $item.module -HieraFindings $hieraFindings
            $hieraEvidence = if ($hieraStatus -eq "ok") { if (@($moduleHiera).Count -gt 0) { "found=$(@($moduleHiera).Count)" } else { "not found" } } else { $hieraStatus }

            $summaryLines += "| $(Escape-MarkdownCell $item.module) | $(Escape-MarkdownCell $item.version) | $(Escape-MarkdownCell $validated) | $(Escape-MarkdownCell $downloads) | $(Escape-MarkdownCell $item.risk) | $(Escape-MarkdownCell $item.confidence) | $(Escape-MarkdownCell $item.review_category) | $(Escape-MarkdownCell $item.evidence_summary) | $(Escape-MarkdownCell $hieraEvidence) |"
        }
    }

    $summaryLines += ""
    $summaryLines += "## Current Interpretation"
    $summaryLines += ""

    if ($primaryItems.Count -gt 0) {
        $summaryLines += "- Primary review target(s): $((@($primaryItems | ForEach-Object { $_.module }) | Sort-Object -Unique) -join ', ')."
    }
    else {
        $summaryLines += "- No primary PostgreSQL management target was identified."
    }

    if ($conditionalItems.Count -gt 0) {
        $summaryLines += "- Conditional review target(s): $((@($conditionalItems | ForEach-Object { $_.module }) | Sort-Object -Unique) -join ', '). These need configuration evidence before treating them as customer impact."
    }

    if ($weakItems.Count -gt 0) {
        $summaryLines += "- Weak or generic evidence was found in $($weakItems.Count) module(s). These should not drive conclusions without stronger evidence."
    }

    $summaryLines += "- Modules with no PostgreSQL evidence: $($noEvidenceItems.Count)."

    if ($hieraStatus -eq "ok" -and $hieraFindings.Count -eq 0) {
        $summaryLines += "- No Hiera/control-repo evidence was found in the scanned path."
    }
    elseif ($hieraStatus -eq "path_missing") {
        $summaryLines += "- Hiera/control-repo path was missing, so no usage validation was performed."
    }
    elseif ($hieraFindings.Count -gt 0) {
        $summaryLines += "- Hiera/control-repo evidence was found. Review the Hiera evidence section in the full report."
    }

    $summaryLines += ""
    $summaryLines += "## Report Files"
    $summaryLines += ""
    $summaryLines += "- Full report: ``$markdownReportPath``"
    $summaryLines += "- JSON report: ``$jsonReportPath``"
    $summaryLines += "- Error report: ``$errorReportPath``"

    if ($null -ne $HieraScan) {
        $summaryLines += "- Hiera evidence: ``$hieraReportPath``"
    }

    $summaryLines | Out-File -FilePath $summaryReportPath -Encoding utf8

    return [pscustomobject][ordered]@{
        jsonReportPath     = $jsonReportPath
        markdownReportPath = $markdownReportPath
        summaryReportPath  = $summaryReportPath
        errorReportPath    = $errorReportPath
        hieraReportPath    = $hieraReportPath
    }
}

Export-ModuleMember -Function Write-ForgeScanSection, Invoke-PostgreSqlReferenceScan, Invoke-HieraEvidenceScan, Get-ForgeCoverageMetadata, Write-PostgreSqlReferenceReports, Format-NullableNumber
