# Prune corpus to only the languages and CWEs supported by IR-SAM.
#
# Supported host languages: Java, Python, JavaScript, TypeScript
# Supported CWE classes  : CWE-89, CWE-78, CWE-79, CWE-90, CWE-643,
#                          CWE-1336, CWE-22
#
# A repository is KEPT iff:
#   * primary_language is one of the supported host languages, AND
#   * at least one of its target_cwes is in the supported CWE set.
#
# Everything else (Ruby, PHP, "Multiple", or repos whose only target CWEs
# fall outside the IR-SAM scope) is removed from:
#   - manifest.csv
#   - metadata/clone-report.csv
#   - metadata/verification-report.csv
#   - metadata/clone-lock.json
#   - repos/<id>/   (on-disk clone, if any)
#
# Idempotent. Safe to run multiple times.

[CmdletBinding()]
param(
    [string]$Root = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'

$SupportedLanguages = @('Java','Python','JavaScript','TypeScript')
$SupportedCwes      = @('CWE-89','CWE-78','CWE-79','CWE-90','CWE-643','CWE-1336','CWE-22')

function Test-RowInScope {
    param([string]$Language, [string]$Cwes)
    if (-not ($SupportedLanguages -contains $Language)) { return $false }
    if ([string]::IsNullOrWhiteSpace($Cwes)) { return $false }
    foreach ($c in ($Cwes -split ';')) {
        if ($SupportedCwes -contains $c.Trim()) { return $true }
    }
    return $false
}

$manifestPath           = Join-Path $Root 'manifest.csv'
$cloneReportPath        = Join-Path $Root 'metadata\clone-report.csv'
$verificationReportPath = Join-Path $Root 'metadata\verification-report.csv'
$cloneLockPath          = Join-Path $Root 'metadata\clone-lock.json'
$reposDir               = Join-Path $Root 'repos'

Write-Host "Scanning manifest: $manifestPath"
$manifest = Import-Csv -Path $manifestPath

$keep   = @()
$remove = @()
foreach ($row in $manifest) {
    if (Test-RowInScope -Language $row.primary_language -Cwes $row.target_cwes) {
        $keep += $row
    } else {
        $remove += $row
    }
}

Write-Host ("Keeping {0} repos, removing {1} repos." -f $keep.Count, $remove.Count)
if ($remove.Count -gt 0) {
    Write-Host "Removed entries:"
    $remove | ForEach-Object {
        Write-Host (" - {0}  [{1}; {2}]" -f $_.id, $_.primary_language, $_.target_cwes)
    }
}

$removeIds = $remove | ForEach-Object { $_.id }

# --- manifest.csv ----------------------------------------------------------
$keep | Export-Csv -Path $manifestPath -NoTypeInformation -Encoding UTF8

# --- clone-report.csv ------------------------------------------------------
if (Test-Path $cloneReportPath) {
    $cloneRows = Import-Csv -Path $cloneReportPath
    $cloneKeep = $cloneRows | Where-Object { $removeIds -notcontains $_.id }
    $cloneKeep | Export-Csv -Path $cloneReportPath -NoTypeInformation -Encoding UTF8
}

# --- verification-report.csv ----------------------------------------------
if (Test-Path $verificationReportPath) {
    $verRows = Import-Csv -Path $verificationReportPath
    $verKeep = $verRows | Where-Object { $removeIds -notcontains $_.id }
    $verKeep | Export-Csv -Path $verificationReportPath -NoTypeInformation -Encoding UTF8
}

# --- clone-lock.json -------------------------------------------------------
if (Test-Path $cloneLockPath) {
    $lock = Get-Content -Raw -Path $cloneLockPath | ConvertFrom-Json
    $lockKeep = @($lock.repositories | Where-Object { $removeIds -notcontains $_.id })
    $lock.repositories     = $lockKeep
    $lock.repository_count = $lockKeep.Count
    $lock.successful_count = ($lockKeep | Where-Object {
        $_.status -eq 'cloned' -or $_.status -eq 'existing'
    }).Count
    $lock.failed_count     = ($lockKeep | Where-Object {
        $_.status -ne 'cloned' -and $_.status -ne 'existing'
    }).Count
    $lock | ConvertTo-Json -Depth 8 | Set-Content -Path $cloneLockPath -Encoding UTF8
}

# --- repos/<id>/ on-disk clones -------------------------------------------
foreach ($id in $removeIds) {
    $repoPath = Join-Path $reposDir $id
    if (Test-Path $repoPath) {
        Write-Host "Deleting clone: $repoPath"
        # Long-path safe removal; ignore failures on read-only git objects.
        try {
            Remove-Item -LiteralPath $repoPath -Recurse -Force -ErrorAction Stop
        } catch {
            # Retry after clearing read-only attributes (common with .git\objects\pack).
            Get-ChildItem -LiteralPath $repoPath -Recurse -Force |
                ForEach-Object { $_.Attributes = 'Normal' }
            Remove-Item -LiteralPath $repoPath -Recurse -Force
        }
    }
}

Write-Host ""
Write-Host "Done."
Write-Host ("Final corpus size: {0} repositories." -f $keep.Count)
