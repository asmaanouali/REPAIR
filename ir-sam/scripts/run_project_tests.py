"""Project-level (whole-repository) test harness for IR-SAM (Task 2.2).

Reads ``test-phase/project-tests.txt`` (a pipe-delimited manifest of
intentionally-vulnerable open-source repositories), then for each project:

  1. shallow-clones the repository into a local cache (``--cache-dir``);
  2. runs the Stage-A Semgrep detector once over the repository's
     in-scope source subtree, producing a set of normalised findings;
  3. for ``labels=owasp-benchmark`` projects, maps each finding back to its
     ``BenchmarkTestNNNNN`` test case and scores detection precision,
     recall, F1 and the FP/FN rates against the shipped
     ``expectedresults`` ground truth, restricted to the four CWE classes
     IR-SAM targets (89/78/90/643);
  4. runs the full A..G remediation pipeline (``core.pipeline.run_finding``)
     on each in-scope finding and records, per case, the stage reached, the
     remediation outcome (patch synthesised / sound abstention), whether all
     Stage-G gates passed, the residual-CWE count and the latency.

Important methodological note on the compile gate
-------------------------------------------------
Stage-G gate 1 invokes ``javac`` on the rewritten file *in isolation*.
Self-contained snippets compile and so exercise the gate for real, but a
file lifted out of a Maven project (e.g. an OWASP Benchmark servlet) does
not compile without the project's classpath. For such projects the harness
therefore reports the *remediation capability* signal
(patch synthesised + residual-CWE-free) separately from the
all-gates-passed rate, and the per-case ``failing_gate`` column makes the
compile-environment limitation explicit rather than hiding it.

Run from the ir-sam package root:

    python -m scripts.run_project_tests \
        --manifest ../test-phase/project-tests.txt \
        --only owasp-benchmark-java,dvpwa
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from core.detectors.semgrep_runner import SemgrepRunner
from core.pipeline import run_finding
from eval.metrics import (
    DetectionOutcome,
    detection_metrics,
    residual_cwe_count,
)

_IN_SCOPE_CWES = {"89", "78", "90", "643"}
_BENCH_FILE_RE = re.compile(r"(BenchmarkTest\d+)")


@dataclass
class Project:
    id: str
    url: str
    ref: str
    lang: str
    cwes: str
    labels: str
    src: str
    note: str


# --- manifest parsing ------------------------------------------------------


def parse_manifest(path: Path) -> list[Project]:
    projects: list[Project] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields: dict[str, str] = {}
        for part in line.split("|"):
            part = part.strip()
            if "=" not in part:
                continue
            key, _, val = part.partition("=")
            val = val.strip()
            if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
                val = val[1:-1]
            fields[key.strip()] = val
        projects.append(Project(
            id=fields["id"], url=fields["url"], ref=fields.get("ref", ""),
            lang=fields["lang"], cwes=fields.get("cwes", ""),
            labels=fields.get("labels", "none"), src=fields.get("src", ""),
            note=fields.get("note", ""),
        ))
    return projects


# --- clone -----------------------------------------------------------------


def ensure_clone(project: Project, cache_dir: Path) -> Path:
    dst = cache_dir / project.id
    if dst.exists():
        return dst
    cache_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["git", "clone", "--depth", "1"]
    if project.ref:
        cmd += ["--branch", project.ref]
    cmd += [project.url, str(dst)]
    print(f"  cloning {project.url} -> {dst}")
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    return dst


# --- OWASP Benchmark ground truth ------------------------------------------


def load_benchmark_labels(repo: Path) -> dict[str, tuple[bool, str]]:
    """Map BenchmarkTestNNNNN -> (is_real_vulnerability, cwe)."""
    csv_path = repo / "expectedresults-1.2.csv"
    labels: dict[str, tuple[bool, str]] = {}
    for i, raw in enumerate(csv_path.read_text(encoding="utf-8").splitlines()):
        if i == 0 or not raw.strip():
            continue
        parts = raw.split(",")
        if len(parts) < 4:
            continue
        name, _category, real, cwe = parts[0], parts[1], parts[2], parts[3]
        labels[name.strip()] = (real.strip().lower() == "true", cwe.strip())
    return labels


# --- per-finding remediation -----------------------------------------------


@dataclass
class CaseRecord:
    finding_id: str
    file: str
    cwe: str
    interpreter: str
    language: str
    stage_reached: str
    outcome: str           # patched | abstain
    abstention_reason: str
    all_gates_passed: bool
    failing_gate: str
    residual_cwe: int
    latency_seconds: float


def _failing_gate(out) -> str:
    if out.gates is None:
        return ""
    for g in out.gates.gates:
        if not g.passed:
            return g.name
    return ""


def remediate_finding(repo: Path, finding, language: str) -> CaseRecord:
    t0 = time.perf_counter()
    try:
        out = run_finding(repo, finding)
    except Exception as exc:  # defensive: one bad file must not abort the run
        latency = time.perf_counter() - t0
        return CaseRecord(
            finding_id=finding.finding_id,
            file=finding.location.file,
            cwe=",".join(finding.cwe)[:24],
            interpreter=finding.interpreter,
            language=finding.language,
            stage_reached="error",
            outcome="error",
            abstention_reason=str(exc)[:120],
            all_gates_passed=False,
            failing_gate=f"exception:{type(exc).__name__}",
            residual_cwe=-1,
            latency_seconds=round(latency, 4),
        )
    latency = time.perf_counter() - t0
    if out.patched:
        residual = residual_cwe_count(out.patch.patched_source, language)
        outcome = "patched"
    else:
        residual = 0
        outcome = "abstain"
    return CaseRecord(
        finding_id=finding.finding_id,
        file=Path(finding.location.file).name,
        cwe=",".join(finding.cwe)[:24],
        interpreter=finding.interpreter,
        language=finding.language,
        stage_reached=out.stage_reached,
        outcome=outcome,
        abstention_reason=out.abstention_reason or "",
        all_gates_passed=out.all_gates_passed,
        failing_gate=_failing_gate(out),
        residual_cwe=residual,
        latency_seconds=round(latency, 4),
    )


# --- per-project run -------------------------------------------------------


def run_project(runner: SemgrepRunner, project: Project, cache_dir: Path,
                max_remediations: int) -> dict:
    repo = ensure_clone(project, cache_dir)
    scan_root = repo / project.src if project.src else repo
    if not scan_root.exists():
        scan_root = repo

    print(f"  scanning {scan_root} ...")
    outcome = runner.scan(scan_root, languages=(project.lang,))
    findings = tuple(getattr(outcome, "findings", ()) or ())
    in_scope = [
        f for f in findings
        if any(c.split("-")[-1].split(":")[0] in _IN_SCOPE_CWES for c in f.cwe)
        or f.interpreter in {"sql", "shell", "ldap", "xpath"}
    ]
    print(f"  semgrep findings: {len(findings)} (in-scope: {len(in_scope)})")

    result: dict = {
        "project": project.id,
        "url": project.url,
        "language": project.lang,
        "labels": project.labels,
        "n_findings": len(findings),
        "n_in_scope_findings": len(in_scope),
    }

    # --- detection scoring (labelled projects only) ---
    if project.labels == "owasp-benchmark":
        labels = load_benchmark_labels(repo)
        # one labelled item per Benchmark test whose ground-truth CWE is
        # in IR-SAM's scope; flagged iff semgrep produced a finding in it.
        flagged_files: set[str] = set()
        for f in findings:
            m = _BENCH_FILE_RE.search(Path(f.location.file).name)
            if m:
                flagged_files.add(m.group(1))
        det_outcomes = []
        for name, (is_real, cwe) in labels.items():
            if cwe not in _IN_SCOPE_CWES:
                continue
            det_outcomes.append(DetectionOutcome(
                case_id=name,
                is_vulnerable=is_real,
                flagged=name in flagged_files,
            ))
        result["detection"] = detection_metrics(det_outcomes)
        result["detection_n_labeled"] = len(det_outcomes)
        # per-CWE detection breakdown
        per_cwe: dict[str, dict] = {}
        for cwe in sorted(_IN_SCOPE_CWES):
            subset = [
                DetectionOutcome(name, real, name in flagged_files)
                for name, (real, c) in labels.items() if c == cwe
            ]
            if subset:
                per_cwe[f"CWE-{cwe}"] = detection_metrics(subset)
        result["detection_by_cwe"] = per_cwe

    # --- remediation ---
    to_remediate = in_scope[:max_remediations] if max_remediations else in_scope
    cases = [remediate_finding(repo, f, project.lang) for f in to_remediate]
    result["n_remediated"] = len(cases)
    result["cases"] = [asdict(c) for c in cases]

    patched = [c for c in cases if c.outcome == "patched"]
    gate_passed = [c for c in patched if c.all_gates_passed]
    abstained = [c for c in cases if c.outcome == "abstain"]
    result["remediation_summary"] = {
        "patched_synthesized": len(patched),
        "patched_residual_free": sum(1 for c in patched if c.residual_cwe == 0),
        "all_gates_passed": len(gate_passed),
        "abstained": len(abstained),
        "errors": sum(1 for c in cases if c.outcome == "error"),
        "failing_gate_histogram": _histogram(c.failing_gate for c in patched
                                             if not c.all_gates_passed),
        "abstention_reason_histogram": _histogram(
            c.abstention_reason for c in abstained),
    }
    return result


def _histogram(items) -> dict[str, int]:
    out: dict[str, int] = {}
    for it in items:
        if not it:
            continue
        out[it] = out.get(it, 0) + 1
    return out


# --- output ----------------------------------------------------------------


def write_reports(results: list[dict], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "project_results.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8")

    lines = ["IR-SAM Project-Level Test Results",
             "=================================", ""]
    for r in results:
        lines.append(f"[{r['project']}]  ({r['language']}, {r['url']})")
        lines.append(f"  semgrep findings      : {r['n_findings']} "
                     f"(in-scope {r['n_in_scope_findings']})")
        if "detection" in r:
            d = r["detection"]
            lines.append(f"  detection (labelled, {r['detection_n_labeled']} cases)")
            lines.append(f"    precision/recall/F1 : "
                         f"{d['precision']}/{d['recall']}/{d['f1']}")
            lines.append(f"    FP-rate / FN-rate   : "
                         f"{d['false_positive_rate']}/{d['false_negative_rate']}")
            lines.append(f"    confusion TP/FP/TN/FN: "
                         f"{d['tp']}/{d['fp']}/{d['tn']}/{d['fn']}")
            for cwe, dd in r.get("detection_by_cwe", {}).items():
                lines.append(f"      {cwe}: P/R/F1="
                             f"{dd['precision']}/{dd['recall']}/{dd['f1']} "
                             f"(TP/FP/TN/FN={dd['tp']}/{dd['fp']}/{dd['tn']}/{dd['fn']})")
        rs = r["remediation_summary"]
        lines.append(f"  remediation ({r['n_remediated']} findings)")
        lines.append(f"    patch synthesized   : {rs['patched_synthesized']}")
        lines.append(f"    residual-CWE-free   : {rs['patched_residual_free']}")
        lines.append(f"    all Stage-G gates ok: {rs['all_gates_passed']}")
        lines.append(f"    sound abstentions   : {rs['abstained']}")
        if rs["failing_gate_histogram"]:
            lines.append(f"    gate failures       : {rs['failing_gate_histogram']}")
        if rs.get("abstention_reason_histogram"):
            lines.append(f"    abstention reasons  : {rs['abstention_reason_histogram']}")
        lines.append("")
    (out_dir / "project_summary.txt").write_text("\n".join(lines) + "\n",
                                                 encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IR-SAM project-level harness")
    here = Path(__file__).resolve().parents[1]
    parser.add_argument("--manifest", type=Path,
                        default=here.parent / "test-phase" / "project-tests.txt")
    parser.add_argument("--cache-dir", type=Path,
                        default=Path.home() / ".irsam-projects")
    parser.add_argument("--out-dir", type=Path, default=here / "reports")
    parser.add_argument("--only", type=str, default="",
                        help="comma-separated project ids to run")
    parser.add_argument("--max-remediations", type=int, default=200,
                        help="cap remediations per project (0 = no cap)")
    args = parser.parse_args(argv)

    runner = SemgrepRunner(timeout_seconds=1800)
    if not runner.is_available():
        print("ERROR: semgrep binary not on PATH.", file=sys.stderr)
        return 2

    projects = parse_manifest(args.manifest)
    only = {s.strip() for s in args.only.split(",") if s.strip()}
    if only:
        projects = [p for p in projects if p.id in only]

    results = []
    for p in projects:
        print(f"\n=== {p.id} ===")
        try:
            results.append(run_project(runner, p, args.cache_dir,
                                       args.max_remediations))
        except subprocess.CalledProcessError as exc:
            print(f"  clone/scan failed: {exc.stderr[:300] if exc.stderr else exc}",
                  file=sys.stderr)
            results.append({"project": p.id, "url": p.url, "error": str(exc)})

    write_reports(results, args.out_dir)
    print(f"\nWrote reports to {args.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
