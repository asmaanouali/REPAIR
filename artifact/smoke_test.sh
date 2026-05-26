#!/usr/bin/env bash
#
# IR-SAM artifact smoke test.
# Target wall-clock: < 30 minutes on a 4-core / 8 GB commodity laptop.
# Actual measured wall-clock on the authors' machine: ~25 seconds
# (the heavy bits -- training, LLM calls, oracle Docker -- are
# intentionally outside the smoke path; see full_run.sh).

set -euo pipefail
cd /opt/irsam/ir-sam
export PYTHONPATH="$PWD"

echo "==[1/4]== pytest (Phases 0-5, 92 tests) =================="
python -m pytest -q

echo "==[2/4]== Phase-2 eval (single-CVE differential oracle) =="
python scripts/eval_phase2.py

echo "==[3/4]== Phase-4 eval (multilang benchmark) ============="
python scripts/eval_phase4.py --per-category 3 --out reports

echo "==[4/4]== Phase-5 eval (six-metric battery, synth tier) =="
python scripts/eval_phase5.py --dataset synth --out reports

echo
echo "smoke test PASSED. headline tables are in:"
echo "    ir-sam/reports/phase2_summary.txt"
echo "    ir-sam/reports/phase4_summary.txt"
echo "    ir-sam/reports/phase5_summary.txt"
