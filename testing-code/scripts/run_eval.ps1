param(
    [double]$Gate = 0.70
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Resolve-Path (Join-Path $here "..")
Set-Location $root

if (-not (Test-Path "repos")) {
    Write-Host "[run_eval] cloning corpus..."
    & (Join-Path $here "clone-corpus.ps1")
}

Write-Host "[run_eval] verifying corpus..."
& (Join-Path $here "verify-corpus.ps1")

Write-Host "[run_eval] scanning corpus with IR-SAM..."
& (Join-Path $here "run-irsam-scan.ps1")

Write-Host "[run_eval] aggregating..."
python (Join-Path $here "aggregate.py") --gate $Gate
exit $LASTEXITCODE
