param(
    [string]$ReposDir = (Join-Path $PSScriptRoot "..\repos"),
    [string]$OutDir = (Join-Path $PSScriptRoot "..\metadata\irsam-scans"),
    [string]$ApiRoot = (Join-Path $PSScriptRoot "..\..\ir-sam")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$reposFull = [System.IO.Path]::GetFullPath($ReposDir)
$outFull = [System.IO.Path]::GetFullPath($OutDir)
$apiFull = [System.IO.Path]::GetFullPath($ApiRoot)

New-Item -ItemType Directory -Force -Path $outFull | Out-Null

if (-not (Test-Path (Join-Path $apiFull "core\cli.py"))) {
    throw "IR-SAM core not found at $apiFull"
}

$env:PYTHONPATH = $apiFull

$repos = Get-ChildItem -Path $reposFull -Directory | Sort-Object Name
foreach ($repo in $repos) {
    $outFile = Join-Path $outFull "$($repo.Name).jsonl"
    Write-Host "Scanning $($repo.Name)"
    $files = Get-ChildItem -Path $repo.FullName -Recurse -File -Include *.java,*.py,*.js,*.ts,*.tsx -ErrorAction SilentlyContinue
    foreach ($file in $files) {
        $record = [ordered]@{
            repository = $repo.Name
            file = $file.FullName
            status = "not_run"
            exit_code = $null
            output = $null
        }
        try {
            $output = & python (Join-Path $apiFull "core\cli.py") pipeline $file.FullName 2>&1
            $record.status = "completed"
            $record.exit_code = $LASTEXITCODE
            $record.output = ($output -join "`n")
        }
        catch {
            $record.status = "failed"
            $record.output = $_.Exception.Message
        }
        ($record | ConvertTo-Json -Compress -Depth 4) | Add-Content -Encoding UTF8 $outFile
    }
}

Write-Host "IR-SAM scan outputs: $outFull"
