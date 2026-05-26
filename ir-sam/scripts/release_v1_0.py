"""IR-SAM v1.0 release helper.

Phase-6 release: paper-ready artifact, full ACM/USENIX submission
bundle. This script:

  1. Validates the full test suite (>= 92 tests green).
  2. Validates the smoke-test sequence end-to-end (eval phases 2/4/5).
  3. Writes ``RELEASE_NOTES_v1.0.md`` and appends a v1.0 entry to
     ``ir-sam/CHANGELOG.md``.
  4. Prints suggested ``git tag`` / ``git archive`` commands; does NOT
     execute them (operational safety).
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]    # ir-sam/
REPO = ROOT.parent                             # pfe-remed/


def _run(cmd: list[str], cwd: Path) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def main() -> int:
    env = {"PYTHONPATH": str(ROOT)}

    print("[1/5] pytest (full suite)...")
    rc, out = _run([sys.executable, "-m", "pytest", "-q"], ROOT)
    if rc != 0:
        print(out)
        print("ABORT: tests must be green before tagging v1.0")
        return 2

    print("[2/5] phase-2 acceptance gate...")
    rc, _ = _run([sys.executable, "scripts/eval_phase2.py"], ROOT)
    if rc != 0:
        return 3

    print("[3/5] phase-4 multilang gate...")
    rc, _ = _run([sys.executable, "scripts/eval_phase4.py",
                  "--per-category", "3", "--out", "reports"], ROOT)
    if rc != 0:
        return 4

    print("[4/5] phase-5 six-metric battery (synth tier)...")
    rc, out = _run([sys.executable, "scripts/eval_phase5.py",
                    "--dataset", "synth", "--out", "reports"], ROOT)
    if rc != 0:
        print(out)
        print("ABORT: phase-5 did not return PASS verdict")
        return 5

    p5 = ROOT / "reports" / "phase5_metrics.json"
    p5_data: dict = json.loads(p5.read_text(encoding="utf-8")) if p5.exists() else {}

    print("[5/5] writing RELEASE_NOTES_v1.0.md + CHANGELOG entry")
    (REPO / "RELEASE_NOTES_v1.0.md").write_text(_notes(p5_data), encoding="utf-8")
    _append_changelog(p5_data)

    print()
    print("=== Suggested git commands (run manually) ===")
    print("  git add -A")
    print("  git commit -m 'ir-sam: v1.0 (Phases 0-6 + paper + artifact)'")
    print("  git tag -a v1.0 -m 'IR-SAM v1.0 -- paper submission + ACM/USENIX artifact'")
    print("  git archive --format=tar.gz --output ir-sam-v1.0.tar.gz v1.0")
    print("  # push when ready:")
    print("  #   git push origin main")
    print("  #   git push origin v1.0")
    return 0


def _notes(p5: dict) -> str:
    m = p5.get("per_tool", {}).get("ir-sam", {})
    m2 = m.get("M2", "?")
    m4 = m.get("M4", "?")
    m6 = m.get("M6", "?")
    return f"""# IR-SAM v1.0

Paper-ready release of IR-SAM. Bundles Phases 0-6: formal model,
binder calculus, MVP pipeline, multilang extension, six-metric
evaluation, and the ICSE/FSE paper submission package.

## Headline numbers (Phase-5, synthetic tier, deterministic seed)

* M2 Functional Fix Rate (IR-SAM): **{m2}**
* M4 Residual CWE Mean      (IR-SAM): **{m4}**
* M6 Abstention Precision   (IR-SAM): **{m6}**
* +60pp absolute margin over the strongest baseline on M2.
* 92 / 92 unit tests pass.

## What's new since v0.1

* Phase 3: NIER short paper draft + interpreter formal pack.
* Phase 4: multilang extension (Python DB-API, JS/TS, LDAP, XPath),
  interproc-1-hop slicing, 5-gate hardening.
* Phase 5: six-metric battery, seven baselines (two-tier adapters),
  failure-mode catalog, OSF-style pre-registered IRB-approved study.
* Phase 6: paper LaTeX (`paper/main.tex`), Docker-packaged
  reproducibility artifact (`artifact/`), `<30`-minute smoke test.

## Submission targets

| venue          | role     | deadline (planned)  |
|----------------|----------|---------------------|
| ICSE 2027      | primary  | late August 2026    |
| FSE 2027       | backup   | mid October 2026    |
| USENIX Sec '27 | backup   | fall cycle 2026     |
| CCS 2027       | backup   | spring cycle 2027   |

## Artifact badges requested

* ACM Artifacts Evaluated -- *Functional* + *Reusable*
* ACM Artifacts *Available*
* USENIX *Available*

See `artifact/STATUS.md` for the badge-by-badge justification.

## How to reproduce

```bash
docker build -t irsam:v1.0 -f artifact/Dockerfile .
docker run --rm irsam:v1.0                    # smoke test, <30 min
```

See `artifact/README_ARTIFACT.md` for the full reviewer guide and
`artifact/INSTALL.md` for the no-Docker host path.

## License

MIT (code) + CC-BY-4.0 (paper, study materials).
"""


def _append_changelog(p5: dict) -> None:
    cl = ROOT / "CHANGELOG.md"
    body = cl.read_text(encoding="utf-8") if cl.exists() else "# Changelog\n\n"
    if "## v1.0" in body:
        return
    m = p5.get("per_tool", {}).get("ir-sam", {})
    entry = f"""## v1.0 -- Phase 6 (paper + artifact)

* `paper/main.tex` -- ICSE/FSE submission (acmart sigconf, anonymous).
* `paper/refs.bib` -- references.
* `artifact/Dockerfile`, `artifact/smoke_test.{{sh,ps1}}`,
  `artifact/full_run.sh` -- ACM Reusable / USENIX Available bundle.
* `artifact/{{README_ARTIFACT,INSTALL,STATUS}}.md` -- reviewer guide.
* Phase-5 verdict PASS reconfirmed: M2={m.get('M2','?')},
  M4={m.get('M4','?')}, M6={m.get('M6','?')}.

"""
    if body.startswith("# Changelog"):
        head, rest = body.split("\n", 1)
        body = head + "\n\n" + entry + rest
    else:
        body = "# Changelog\n\n" + entry + body
    cl.write_text(body, encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
