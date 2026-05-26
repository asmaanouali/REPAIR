# Host install (no Docker)

The Docker route in `README_ARTIFACT.md` is the supported path. The
instructions below let a reviewer run the smoke test on their host
directly, e.g., on a hardened evaluation VM that disallows nested
containers.

## Prerequisites

  - Python 3.10.x (3.10.11 - 3.10.14 tested)
  - `pip` >= 23
  - Git
  - 1.5 GB free disk
  - Linux, macOS, or Windows (PowerShell 5.1+)

## Steps

```bash
# 1. clone (or unpack the artifact zip)
git clone <anonymous-url>.git irsam && cd irsam

# 2. create a virtualenv
python -m venv .venv
source .venv/bin/activate                       # Windows: .venv\Scripts\Activate.ps1

# 3. install pinned deps
pip install -r artifact/requirements.txt

# 4. run the smoke test
export PYTHONPATH=$PWD/ir-sam                   # Windows: $env:PYTHONPATH="$PWD\ir-sam"
bash artifact/smoke_test.sh                     # Windows: see PS one-liner below
```

### PowerShell one-liner (Windows)

```powershell
cd ir-sam
$env:PYTHONPATH = $PWD
python -m pytest -q
python scripts/eval_phase2.py
python scripts/eval_phase4.py --per-category 3 --out reports
python scripts/eval_phase5.py --dataset synth --out reports
```

## Optional: real-tier baselines

```bash
export OPENAI_API_KEY=sk-...
export IRSAM_VULREPAIR_CKPT=/path/to/vulrepair_codet5.pt
export IRSAM_SEQTRANS_CKPT=/path/to/seqtrans.pt
export IRSAM_EVAL_CORPUS_DIR=/path/to/cvefixes_root
bash artifact/full_run.sh
```

Each adapter checks the relevant env var and silently falls back to
its deterministic synthetic stub when the resource is missing.

## Troubleshooting

  - **Pytest cannot find `core` / `bench`.** Set `PYTHONPATH`
    explicitly per the snippets above; `conftest.py` only patches the
    pytest run, not ad-hoc script invocation.
  - **ReportLab installation fails on Windows.** `pip install
    reportlab==4.4.10 --only-binary=:all:` forces the wheel.
  - **Different M2 numbers than the paper.** The synthetic tier is
    deterministic; report this as a bug via the anonymous channel.
