#!/usr/bin/env bash
# Full corpus evaluation: clone, scan, aggregate, gate.
#
# Usage:   bash scripts/run_eval.sh
# Outputs: testing-code/results/{summary.csv, summary.md, by_cwe.csv}
# Exit:    0 iff aggregated M1 >= 0.70.
set -euo pipefail

cd "$(dirname "$0")/.."

if [[ ! -d repos ]]; then
    echo "[run_eval] cloning corpus..."
    pwsh -NoProfile -File scripts/clone-corpus.ps1
fi

echo "[run_eval] verifying corpus..."
pwsh -NoProfile -File scripts/verify-corpus.ps1

echo "[run_eval] scanning corpus with IR-SAM..."
pwsh -NoProfile -File scripts/run-irsam-scan.ps1

echo "[run_eval] aggregating..."
python3 scripts/aggregate.py --gate 0.70
