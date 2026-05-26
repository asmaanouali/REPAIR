# IR-SAM artifact smoke test (PowerShell).
# Mirrors artifact/smoke_test.sh for Windows reviewers.
# Target wall-clock: < 30 minutes on a 4-core / 8 GB commodity laptop.
$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent $PSScriptRoot
Set-Location (Join-Path $repo "ir-sam")
$env:PYTHONPATH = (Get-Location).Path

Write-Host "==[1/4]== pytest (Phases 0-5, 92 tests) =================="
python -m pytest -q

Write-Host "==[2/4]== Phase-2 eval ===================================="
python scripts/eval_phase2.py

Write-Host "==[3/4]== Phase-4 eval (multilang benchmark) =============="
python scripts/eval_phase4.py --per-category 3 --out reports

Write-Host "==[4/4]== Phase-5 eval (six-metric battery, synth tier) ==="
python scripts/eval_phase5.py --dataset synth --out reports

Write-Host ""
Write-Host "smoke test PASSED. headline tables are in:"
Write-Host "    ir-sam/reports/phase2_summary.txt"
Write-Host "    ir-sam/reports/phase4_summary.txt"
Write-Host "    ir-sam/reports/phase5_summary.txt"
