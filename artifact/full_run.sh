#!/usr/bin/env bash
#
# Full re-run of every empirical claim in the paper. Includes the
# (optional) real-tier baselines IF the relevant environment is set:
#
#   OPENAI_API_KEY            -> activates CodeQL+GPT-4, ChatRepair,
#                                LLM-zero-shot real tier
#   IRSAM_VULREPAIR_CKPT      -> activates VulRepair real tier
#   IRSAM_SEQTRANS_CKPT       -> activates SeqTrans real tier
#   IRSAM_EVAL_CORPUS_DIR     -> activates CVEfixes/Vul4J/BigVul real corpus
#   IR_SAM_USE_DOCKER_ORACLE  -> activates multi-engine oracle backend
#
# Wall-clock without any of those: ~1 minute (synthetic tier).
# With all of them: dataset-dependent (CVEfixes ~ 2-4 hours).

set -euo pipefail
cd /opt/irsam/ir-sam
export PYTHONPATH="$PWD"

echo "==[1/5]== Full pytest suite =============================="
python -m pytest -q --cov=core --cov=eval --cov=bench --cov-report=term-missing

echo "==[2/5]== Phase-2 eval ==================================="
python scripts/eval_phase2.py

echo "==[3/5]== Phase-4 eval ==================================="
python scripts/eval_phase4.py --per-category 3 --out reports

echo "==[4/5]== Phase-5 eval (all available datasets) =========="
if [ -n "${IRSAM_EVAL_CORPUS_DIR:-}" ]; then
  python scripts/eval_phase5.py --dataset all --out reports
else
  python scripts/eval_phase5.py --dataset synth --out reports
fi

echo "==[5/5]== Re-build every phase PDF ======================="
cd /opt/irsam
python build_phase2_pdf.py
python build_phase3_paper.py
python build_phase4_pdf.py
python build_phase5_pdf.py
python build_phase6_pdf.py

echo
echo "full re-run PASSED. PDFs are in /opt/irsam/IR-SAM_Phase*.pdf"
