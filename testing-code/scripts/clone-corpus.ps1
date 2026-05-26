param(
    [string]$ManifestPath = (Join-Path $PSScriptRoot "..\manifest.csv"),
    [string]$ReposDir = (Join-Path $PSScriptRoot "..\repos"),
    [string]$MetadataDir = (Join-Path $PSScriptRoot "..\metadata"),
    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-FullPath([string]$PathValue) {
    return [System.IO.Path]::GetFullPath($PathValue)
}

function Invoke-Git([string[]]$Arguments, [string]$WorkingDirectory = $null) {
    $previous = Get-Location
    $previousErrorAction = $ErrorActionPreference
    try {
        if ($WorkingDirectory) {
            Set-Location $WorkingDirectory
        }
        $ErrorActionPreference = "Continue"
        $output = & git @Arguments 2>&1
        $exitCode = $LASTEXITCODE
        return [pscustomobject]@{ ExitCode = $exitCode; Output = (($output | Out-String).Trim()) }
    }
    finally {
        $ErrorActionPreference = $previousErrorAction
        Set-Location $previous
    }
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "git is required but was not found on PATH."
}

$manifestFull = Resolve-FullPath $ManifestPath
$reposFull = Resolve-FullPath $ReposDir
$metadataFull = Resolve-FullPath $MetadataDir

if (-not (Test-Path $manifestFull)) {
    throw "Manifest not found: $manifestFull"
}

New-Item -ItemType Directory -Force -Path $reposFull | Out-Null
New-Item -ItemType Directory -Force -Path $metadataFull | Out-Null

$rows = @(Import-Csv $manifestFull)
$started = (Get-Date).ToUniversalTime().ToString("o")
$results = New-Object System.Collections.Generic.List[object]

foreach ($row in $rows) {
    $target = Join-Path $reposFull $row.id
    $status = "cloned"
    $message = ""
    $commit = ""
    $branch = ""
    $remote = $row.url

    try {
        if ((Test-Path $target) -and $Force) {
            Remove-Item -Recurse -Force $target
        }

        if (Test-Path (Join-Path $target ".git")) {
            $status = "existing"
        }
        elseif (Test-Path $target) {
            throw "Target exists but is not a git clone: $target"
        }
        else {
            Write-Host "Cloning $($row.repository) -> $target"
            $clone = Invoke-Git -Arguments @("-c", "core.longpaths=true", "clone", "--depth", "1", "--single-branch", $row.url, $target)
            if ($clone.ExitCode -ne 0) {
                throw $clone.Output
            }
        }

        $commitResult = Invoke-Git -Arguments @("rev-parse", "HEAD") -WorkingDirectory $target
        if ($commitResult.ExitCode -eq 0) {
            $commit = $commitResult.Output.Trim()
        }

        $branchResult = Invoke-Git -Arguments @("rev-parse", "--abbrev-ref", "HEAD") -WorkingDirectory $target
        if ($branchResult.ExitCode -eq 0) {
            $branch = $branchResult.Output.Trim()
        }

        $remoteResult = Invoke-Git -Arguments @("remote", "get-url", "origin") -WorkingDirectory $target
        if ($remoteResult.ExitCode -eq 0) {
            $remote = $remoteResult.Output.Trim()
        }
    }
    catch {
        $status = "failed"
        $message = $_.Exception.Message
        Write-Warning "Failed $($row.repository): $message"
    }

    $results.Add([pscustomobject]@{
        id = $row.id
        repository = $row.repository
        url = $row.url
        local_path = $target
        status = $status
        branch = $branch
        commit = $commit
        remote = $remote
        primary_language = $row.primary_language
        target_cwes = $row.target_cwes
        cloned_at_utc = $started
        message = $message
    })
}

$reportPath = Join-Path $metadataFull "clone-report.csv"
$lockPath = Join-Path $metadataFull "clone-lock.json"
$resultArray = @($results.ToArray())

$resultArray | Export-Csv -NoTypeInformation -Encoding UTF8 $reportPath
$lock = [pscustomobject]@{
    generated_at_utc = $started
    manifest = $manifestFull
    repository_count = @($rows).Count
    successful_count = @($resultArray | Where-Object { @("cloned", "existing") -contains $_.status }).Count
    failed_count = @($resultArray | Where-Object { $_.status -eq "failed" }).Count
    repositories = $resultArray
}
$lock | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $lockPath

Write-Host "Clone report: $reportPath"
Write-Host "Lockfile: $lockPath"
Write-Host "Successful: $($lock.successful_count) / $($lock.repository_count)"

if ($lock.failed_count -gt 0) {
    Write-Warning "$($lock.failed_count) repositories failed. See clone-report.csv."
    exit 2
}
