param(
    [string]$ManifestPath = (Join-Path $PSScriptRoot "..\manifest.csv"),
    [string]$ReposDir = (Join-Path $PSScriptRoot "..\repos"),
    [string]$MetadataDir = (Join-Path $PSScriptRoot "..\metadata")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-FullPath([string]$PathValue) {
    return [System.IO.Path]::GetFullPath($PathValue)
}

function Invoke-Git([string[]]$Arguments, [string]$WorkingDirectory) {
    $previous = Get-Location
    $previousErrorAction = $ErrorActionPreference
    try {
        Set-Location $WorkingDirectory
        $ErrorActionPreference = "Continue"
        $output = & git @Arguments 2>&1
        $exitCode = $LASTEXITCODE
        return [pscustomobject]@{
            ExitCode = $exitCode
            Output = (($output | Out-String).Trim())
        }
    }
    finally {
        $ErrorActionPreference = $previousErrorAction
        Set-Location $previous
    }
}

function Get-SourceFiles([string]$Root) {
    $sourceExtensions = New-Object 'System.Collections.Generic.HashSet[string]'
    @(".java", ".py", ".js", ".ts", ".tsx", ".php", ".rb", ".cs") |
        ForEach-Object { [void]$sourceExtensions.Add($_) }
    $skipPattern = "[\\/](\.git|node_modules|vendor|dist|build|target|coverage|\.venv|venv|__pycache__|\.next|\.cache)[\\/]"

    return @(Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $sourceExtensions.Contains($_.Extension.ToLowerInvariant()) -and
            ($_.FullName -notmatch $skipPattern)
        })
}

function Count-PatternMatches($Files) {
    $patterns = @(
        "executeQuery", "createStatement", "prepareStatement", "cursor.execute",
        "db.query", "sequelize.query", "ldap", "xpath", "child_process",
        "exec(", "eval(", "render_template_string", "sendFile", "path.join"
    )
    $count = 0
    foreach ($file in $Files) {
        try {
            if ($file.Length -gt 2097152) {
                continue
            }
            $text = Get-Content -Raw -ErrorAction Stop $file.FullName
            foreach ($pattern in $patterns) {
                if ($text.IndexOf($pattern, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                    $count += 1
                    break
                }
            }
        }
        catch {
            continue
        }
    }
    return $count
}

$manifestFull = Resolve-FullPath $ManifestPath
$reposFull = Resolve-FullPath $ReposDir
$metadataFull = Resolve-FullPath $MetadataDir

if (-not (Test-Path $manifestFull)) {
    throw "Manifest not found: $manifestFull"
}

New-Item -ItemType Directory -Force -Path $metadataFull | Out-Null

$rows = @(Import-Csv $manifestFull)
$verifiedAt = (Get-Date).ToUniversalTime().ToString("o")
$results = New-Object System.Collections.Generic.List[object]

foreach ($row in $rows) {
    $target = Join-Path $reposFull $row.id
    $status = "missing"
    $commit = ""
    $branch = ""
    $sourceFiles = 0
    $targetEvidenceFiles = 0
    $message = ""

    try {
        Write-Host "Verifying $($row.id)"
        if (-not (Test-Path (Join-Path $target ".git"))) {
            throw "local clone missing"
        }

        $status = "present"
        $commitResult = Invoke-Git -Arguments @("rev-parse", "HEAD") -WorkingDirectory $target
        if ($commitResult.ExitCode -eq 0) {
            $commit = $commitResult.Output.Trim()
        }
        $branchResult = Invoke-Git -Arguments @("rev-parse", "--abbrev-ref", "HEAD") -WorkingDirectory $target
        if ($branchResult.ExitCode -eq 0) {
            $branch = $branchResult.Output.Trim()
        }

        $sourceFileList = Get-SourceFiles $target
        $sourceFiles = @($sourceFileList).Count
        $targetEvidenceFiles = Count-PatternMatches $sourceFileList
    }
    catch {
        $message = $_.Exception.Message
        Write-Warning "Verification issue for $($row.id): $message"
    }

    $results.Add([pscustomobject]@{
        id = $row.id
        repository = $row.repository
        status = $status
        branch = $branch
        commit = $commit
        primary_language = $row.primary_language
        target_cwes = $row.target_cwes
        source_file_count = $sourceFiles
        target_pattern_file_count = $targetEvidenceFiles
        verified_at_utc = $verifiedAt
        message = $message
    })
}

$reportPath = Join-Path $metadataFull "verification-report.csv"
$resultArray = @($results.ToArray())
$resultArray | Export-Csv -NoTypeInformation -Encoding UTF8 $reportPath

$present = @($resultArray | Where-Object { $_.status -eq "present" }).Count
Write-Host "Verification report: $reportPath"
Write-Host "Present clones: $present / $($rows.Count)"

if ($present -ne $rows.Count) {
    Write-Warning "Some repositories are missing. Run clone-corpus.ps1 first or inspect the report."
    exit 2
}
