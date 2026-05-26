"""IR-SAM v0.1 release helper.

This script prepares the artifacts associated with tag
``ir-sam-mvp/v0.1`` but it does *not* execute any push / tag /
delete operation. It only:

  1. Validates that `pytest` is green and that
     ``scripts/eval_phase2.py`` exits with rc=0 (acceptance gate).
  2. Writes a ``RELEASE_NOTES_v0.1.md`` summary in the workspace root.
  3. Prints, on stdout, the *suggested* ``git tag`` / ``git archive``
     commands so a human can review and run them.

Operational safety: every destructive or shared-state action
(push, tag, archive distribution) must remain a manual step.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]   # ir-sam/
REPO = ROOT.parent                            # pfe-remed/


def _run(cmd: list[str], cwd: Path) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main() -> int:
    print("[1/3] pytest...")
    rc, out = _run([sys.executable, "-m", "pytest", "-q"], ROOT)
    if rc != 0:
        print(out)
        print("ABORT: tests must be green before tagging v0.1")
        return 2

    print("[2/3] phase2 acceptance gate...")
    rc, out = _run([sys.executable, "scripts/eval_phase2.py",
                    "--per-category", "5"], ROOT)
    if rc != 0:
        print(out)
        print("ABORT: phase2 evaluation did not meet the acceptance gate")
        return 3

    data = {}
    eval_json = ROOT / "reports" / "phase2_eval.json"
    if eval_json.exists():
        data = json.loads(eval_json.read_text(encoding="utf-8")).get("summary", {})

    print("[3/3] writing RELEASE_NOTES_v0.1.md")
    notes = REPO / "RELEASE_NOTES_v0.1.md"
    notes.write_text(_release_notes(data), encoding="utf-8")
    print(f"  -> {notes}")

    print()
    print("=== Suggested git commands (run manually) ===")
    print("  git add -A")
    print("  git commit -m 'ir-sam: v0.1 MVP (Phases 0-2)'")
    print("  git tag -a ir-sam-mvp/v0.1 \\")
    print("    -m 'IR-SAM v0.1 MVP: CWE-089 / Java+JDBC; "
          f"{data.get('patch_gate_pass_rate', 0)*100:.2f}% gate-pass, "
          f"{data.get('residual_cwe89', '?')} residual'")
    print("  git archive --format=tar.gz --output ir-sam-mvp-v0.1.tar.gz "
          "ir-sam-mvp/v0.1")
    print("  # push when ready:  git push --tags")
    return 0


def _release_notes(s: dict) -> str:
    gp = s.get("patch_gate_pass_rate", 0) * 100
    res = s.get("residual_cwe89", "?")
    n = s.get("total_cases", "?")
    return f"""# IR-SAM v0.1 (`ir-sam-mvp/v0.1`)

First publishable artifact of the IR-SAM PhD research programme. This
release packages Phases 0--2: the formal model (IAM/SIG), the binder
catalog DSL, and the end-to-end MVP pipeline (CWE-089, Java + JDBC).

## Acceptance gate (live numbers)

* Patch gate-pass rate: **{gp:.2f}%**
* Residual CWE-089: **{res}**
* Synthetic benchmark size: **{n} cases**
* All five validator gates wired (compile / regression / structural /
  re-SAST / differential).

## What is in the box

* `ir-sam/binders/sql_jdbc.yaml` -- binder catalog with placeholder-style
  and parameterizing-API maps.
* `ir-sam/core/{{ingest,slicer,recon,parsers,iam,phi,rewriter,validator,
  pipeline}}/` -- stages A--G.
* `ir-sam/bench/juliet_mini/` -- 50-case synthetic benchmark.
* `ir-sam/scripts/eval_phase2.py` -- acceptance harness.
* `IR-SAM_Phase0-1.pdf`, `IR-SAM_Phase2.pdf` -- written deliverables.

## What is NOT in v0.1

* No Python / JS / TS support (delivered in v0.2.0-multilang).
* No LDAP / XPath / OS-command coverage.
* No inter-procedural slicing.
* No LM-assisted disambiguation.
* Differential oracle is in-process SQLite only.

## Reproducibility

```
cd ir-sam
python -m pytest -q
python scripts/eval_phase2.py --per-category 5
```

## Companion paper

A short paper ("IR-SAM: Intent-Reconstructive Secure API Migration")
targeting **NIER / SecDev / ICSE-SEIP** is shipped as
`IR-SAM_Phase3_NIER.pdf` in the same workspace.
"""


if __name__ == "__main__":
    sys.exit(main())
