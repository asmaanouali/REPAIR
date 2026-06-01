"""Snippet-level test harness for IR-SAM (Task 2.1).

Parses ``test-phase/snippet-tests.txt`` (a ``@@@`` / ``@@@END`` delimited
corpus of minimal, provenance-annotated injection snippets), then for each
snippet:

  1. materialises it to a temp file with the right extension;
  2. runs the Stage-A Semgrep detector over the snippet directory to obtain
     the *detection* signal (flagged / not flagged) used to score precision,
     recall, F1 and the FP/FN rates against the ``vulnerable`` ground truth;
  3. runs the full A..G remediation pipeline (``core.pipeline.run_file``) to
     obtain the *remediation* outcome (patched / abstained / clean) and the
     wall-clock latency, and checks it against the ``expect`` label;
  4. for patched cases, re-scans the rewritten source to confirm the residual
     CWE count is zero (M4 == 0).

Outputs (written under ``reports/``):

  * ``snippet_results.json`` -- per-case records + aggregate metrics
  * ``snippet_results.csv``  -- one row per case
  * ``snippet_summary.txt``  -- human-readable summary

Run from the ir-sam package root:

    python -m scripts.run_snippet_tests \
        --corpus ../test-phase/snippet-tests.txt

The harness is deterministic and offline (semgrep uses the shipped local
ruleset; the pipeline uses the in-repo binder catalogs).
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from core.detectors.semgrep_runner import SemgrepRunner
from core.pipeline import run_file, run_finding
from eval.metrics import (
    DetectionOutcome,
    detection_metrics,
    residual_cwe_count,
)

_EXT = {"java": ".java", "python": ".py"}


@dataclass(frozen=True)
class Snippet:
    id: str
    cwe: str
    lang: str
    interpreter: str
    vulnerable: bool
    expect: str          # patched | abstain | clean
    provenance: str
    code: str


# --- corpus parsing --------------------------------------------------------


def _parse_header(line: str) -> dict[str, str]:
    # "@@@ k=v | k=v | k="quoted value"" -> dict
    body = line[len("@@@"):].strip()
    out: dict[str, str] = {}
    for part in body.split("|"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, val = part.partition("=")
        val = val.strip()
        if len(val) >= 2 and val[0] == '"' and val[-1] == '"':
            val = val[1:-1]
        out[key.strip()] = val
    return out


def parse_corpus(path: Path) -> list[Snippet]:
    snippets: list[Snippet] = []
    header: dict[str, str] | None = None
    code_lines: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.startswith("@@@END"):
            if header is None:
                raise ValueError("@@@END without a preceding @@@ header")
            snippets.append(Snippet(
                id=header["id"],
                cwe=header["cwe"],
                lang=header["lang"],
                interpreter=header["interpreter"],
                vulnerable=header["vulnerable"].lower() == "true",
                expect=header["expect"],
                provenance=header.get("provenance", ""),
                code="\n".join(code_lines).strip("\n") + "\n",
            ))
            header = None
            code_lines = []
        elif raw.startswith("@@@"):
            header = _parse_header(raw)
            code_lines = []
        elif header is not None:
            code_lines.append(raw)
        # lines before the first header (comments) are ignored
    return snippets


# --- per-snippet run -------------------------------------------------------


@dataclass
class SnippetResult:
    id: str
    cwe: str
    lang: str
    interpreter: str
    vulnerable: bool
    expect: str
    # detection
    flagged: bool
    detector_rule_ids: str
    # remediation
    stage_reached: str
    outcome: str          # patched | abstain | clean
    abstention_reason: str | None
    all_gates_passed: bool
    failing_gate: str
    latency_seconds: float
    residual_cwe: int
    # verdicts
    detection_correct: bool
    remediation_correct: bool
    provenance: str


def _detect(runner: SemgrepRunner, snippet: Snippet, workdir: Path):
    """Return (flagged, comma-separated rule ids, findings) for the snippet."""
    outcome = runner.scan(workdir, languages=(snippet.lang,))
    findings = tuple(getattr(outcome, "findings", ()) or ())
    rule_ids = sorted({f.detector_rule_id.split(".")[-1] for f in findings})
    return (len(findings) > 0), ",".join(rule_ids), findings


def _remediate(workdir: Path, file_path: Path, snippet: Snippet, findings):
    """Return (stage_reached, outcome, abstention_reason, all_gates_passed,
    failing_gate, latency, residual).

    The faithful end-to-end route is detector-driven: each normalised
    finding carries its own ``(language, interpreter)`` tuple, which selects
    the pipeline backend. SQL findings reach a registered rewriter; the
    command/LDAP/XPath interpreters have no registered rewriter yet and so
    return a sound ``unsupported_backend`` abstention rather than an unsafe
    patch. When the detector produced no finding (a safe negative control),
    there is nothing to remediate and the case is reported as ``clean``.
    """
    t0 = time.perf_counter()
    if not findings:
        # Fall back to the file-based Java/Python-SQL locator so that a
        # genuinely sink-free snippet is still exercised by Stage A.
        out = run_file(file_path)
        latency = time.perf_counter() - t0
        if out.patched:
            residual = residual_cwe_count(out.patch.patched_source, snippet.lang)
            return (out.stage_reached, "patched", None, out.all_gates_passed,
                    _failing_gate(out), latency, residual)
        return out.stage_reached, "clean", out.abstention_reason, True, "", latency, 0

    out = run_finding(workdir, findings[0])
    latency = time.perf_counter() - t0
    if out.patched:
        residual = residual_cwe_count(out.patch.patched_source, snippet.lang)
        return (out.stage_reached, "patched", None, out.all_gates_passed,
                _failing_gate(out), latency, residual)
    return out.stage_reached, "abstain", out.abstention_reason, True, "", latency, 0


def _failing_gate(out) -> str:
    """Name of the first failed Stage-G gate, or '' if all passed/none ran."""
    if out.gates is None:
        return ""
    for g in out.gates.gates:
        if not g.passed:
            return g.name
    return ""


def run_snippet(runner: SemgrepRunner, snippet: Snippet) -> SnippetResult:
    with tempfile.TemporaryDirectory(prefix="irsam-snip-") as td:
        ext = _EXT[snippet.lang]
        fp = Path(td) / f"{snippet.id}{ext}"
        fp.write_text(snippet.code, encoding="utf-8")

        flagged, rule_ids, findings = _detect(runner, snippet, Path(td))
        (stage, outcome, reason, all_gates_passed, failing_gate,
         latency, residual) = _remediate(Path(td), fp, snippet, findings)

    detection_correct = flagged == snippet.vulnerable
    remediation_correct = outcome == snippet.expect

    return SnippetResult(
        id=snippet.id,
        cwe=snippet.cwe,
        lang=snippet.lang,
        interpreter=snippet.interpreter,
        vulnerable=snippet.vulnerable,
        expect=snippet.expect,
        flagged=flagged,
        detector_rule_ids=rule_ids,
        stage_reached=stage,
        outcome=outcome,
        abstention_reason=reason,
        all_gates_passed=all_gates_passed,
        failing_gate=failing_gate,
        latency_seconds=round(latency, 4),
        residual_cwe=residual,
        detection_correct=detection_correct,
        remediation_correct=remediation_correct,
        provenance=snippet.provenance,
    )


# --- aggregation -----------------------------------------------------------


def aggregate(results: list[SnippetResult]) -> dict:
    det_outcomes = [
        DetectionOutcome(case_id=r.id, is_vulnerable=r.vulnerable, flagged=r.flagged)
        for r in results
    ]
    det = detection_metrics(det_outcomes)

    n = len(results)
    remediation_accuracy = (
        sum(1 for r in results if r.remediation_correct) / n if n else 0.0
    )
    # patch-correctness rate over the cases we *expected* a patch for
    patch_expected = [r for r in results if r.expect == "patched"]
    patch_correct = sum(
        1 for r in patch_expected
        if r.outcome == "patched" and r.residual_cwe == 0
    )
    patch_correctness_rate = (
        patch_correct / len(patch_expected) if patch_expected else 0.0
    )
    # of the synthesized patches, how many cleared all Stage-G gates
    # (compile + regression + structural + re-SAST + differential)?
    synthesized = [r for r in results if r.outcome == "patched"]
    gate_passed = sum(1 for r in synthesized if r.all_gates_passed)
    gate_pass_rate = gate_passed / len(synthesized) if synthesized else 0.0
    # abstention soundness: of the cases we expected to abstain, how many did?
    abstain_expected = [r for r in results if r.expect == "abstain"]
    abstain_sound = sum(1 for r in abstain_expected if r.outcome == "abstain")
    abstention_soundness = (
        abstain_sound / len(abstain_expected) if abstain_expected else 1.0
    )
    latencies = sorted(r.latency_seconds for r in results)
    median_latency = (
        latencies[len(latencies) // 2] if latencies else 0.0
    )

    by_cwe: dict[str, dict[str, int]] = {}
    for r in results:
        d = by_cwe.setdefault(r.cwe, {"n": 0, "detected": 0, "remediation_ok": 0})
        d["n"] += 1
        if r.detection_correct:
            d["detected"] += 1
        if r.remediation_correct:
            d["remediation_ok"] += 1

    return {
        "n_snippets": n,
        "detection": det,
        "remediation_accuracy": round(remediation_accuracy, 4),
        "patch_correctness_rate": round(patch_correctness_rate, 4),
        "patch_expected": len(patch_expected),
        "patch_correct": patch_correct,
        "gate_pass_rate": round(gate_pass_rate, 4),
        "gate_passed": gate_passed,
        "synthesized": len(synthesized),
        "abstention_soundness": round(abstention_soundness, 4),
        "abstain_expected": len(abstain_expected),
        "abstain_sound": abstain_sound,
        "median_latency_seconds": round(median_latency, 4),
        "residual_cwe_total": sum(r.residual_cwe for r in results),
        "by_cwe": by_cwe,
    }


# --- output ----------------------------------------------------------------


def write_reports(results: list[SnippetResult], agg: dict, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    (out_dir / "snippet_results.json").write_text(
        json.dumps({"results": [asdict(r) for r in results], "aggregate": agg},
                   indent=2),
        encoding="utf-8",
    )

    with (out_dir / "snippet_results.csv").open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(asdict(results[0]).keys()))
        writer.writeheader()
        for r in results:
            writer.writerow(asdict(r))

    det = agg["detection"]
    lines = [
        "IR-SAM Snippet-Level Test Results",
        "=================================",
        f"snippets               : {agg['n_snippets']}",
        "",
        "Detection (Stage-A localisation vs ground-truth label)",
        f"  precision            : {det['precision']}",
        f"  recall               : {det['recall']}",
        f"  F1                   : {det['f1']}",
        f"  false-positive rate  : {det['false_positive_rate']}",
        f"  false-negative rate  : {det['false_negative_rate']}",
        f"  accuracy             : {det['accuracy']}",
        f"  confusion (TP/FP/TN/FN): {det['tp']}/{det['fp']}/{det['tn']}/{det['fn']}",
        "",
        "Remediation (A..G outcome vs expected)",
        f"  remediation accuracy : {agg['remediation_accuracy']}",
        f"  patch-correctness    : {agg['patch_correctness_rate']} "
        f"({agg['patch_correct']}/{agg['patch_expected']})",
        f"  Stage-G gate-pass    : {agg['gate_pass_rate']} "
        f"({agg['gate_passed']}/{agg['synthesized']} synthesized patches)",
        f"  abstention soundness : {agg['abstention_soundness']} "
        f"({agg['abstain_sound']}/{agg['abstain_expected']})",
        f"  residual CWE total   : {agg['residual_cwe_total']}",
        f"  median latency (s)   : {agg['median_latency_seconds']}",
        "",
        "Per-CWE breakdown (detected / remediation-ok / n)",
    ]
    for cwe, d in sorted(agg["by_cwe"].items()):
        lines.append(f"  {cwe:10s}: {d['detected']}/{d['remediation_ok']}/{d['n']}")
    (out_dir / "snippet_summary.txt").write_text("\n".join(lines) + "\n",
                                                 encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="IR-SAM snippet-level harness")
    here = Path(__file__).resolve().parents[1]
    parser.add_argument(
        "--corpus", type=Path,
        default=here.parent / "test-phase" / "snippet-tests.txt",
    )
    parser.add_argument(
        "--out-dir", type=Path, default=here / "reports",
    )
    args = parser.parse_args(argv)

    runner = SemgrepRunner()
    if not runner.is_available():
        print("ERROR: semgrep binary not on PATH; detection metrics need it.",
              file=sys.stderr)
        return 2

    snippets = parse_corpus(args.corpus)
    print(f"Loaded {len(snippets)} snippets from {args.corpus}")
    results = []
    for s in snippets:
        r = run_snippet(runner, s)
        results.append(r)
        det = "FLAG" if r.flagged else "----"
        dv = "ok" if r.detection_correct else "XX"
        rv = "ok" if r.remediation_correct else "XX"
        print(f"  {s.id:34s} det[{det} {dv:2s}] rem[{r.outcome:8s} {rv:2s}] "
              f"{r.latency_seconds:.3f}s")

    agg = aggregate(results)
    write_reports(results, agg, args.out_dir)
    print(f"\nWrote reports to {args.out_dir}")
    print(f"Detection F1={agg['detection']['f1']}  "
          f"patch-correctness={agg['patch_correctness_rate']}  "
          f"abstention-soundness={agg['abstention_soundness']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
