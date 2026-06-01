"""The six Phase-5 evaluation metrics (contribution \u00a76.2).

  M1. Patch Applicability          -- did the tool emit any rewrite?
  M2. Functional Fix Rate          -- post-patch passes the project
                                       test-suite *and* the differential
                                       oracle (no payload alters the
                                       row-set / DIT-entry-set / node-set).
  M3. Semantic Equivalence         -- on benign inputs, the patched output
                                       matches the ground-truth fix
                                       (token-Jaccard \u2265 \u03c4 and
                                       interpreter row-set equality).
  M4. Residual CWE Density         -- count of re-SAST findings on the
                                       patched source for the original CWE.
  M5. Median End-to-End Latency    -- wall-clock seconds per case.
  M6. Abstention Precision         -- of the cases the tool *refused* to
                                       patch, what fraction did the ground
                                       truth also leave structurally
                                       irreparable (multi-file fix, schema
                                       change, behavior-altering)? -- i.e.,
                                       the tool refused for the right reason.

All six metrics return values in [0,1] except M4 (raw count) and M5 (sec).
"""

from __future__ import annotations

import re
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Sequence


# --- per-case observation (the unit of evidence) ---


@dataclass
class CaseObservation:
    case_id: str
    tool: str
    applied: bool                  # M1 contribution
    functional_pass: bool          # M2 contribution
    benign_equivalent: bool        # M3 contribution
    residual_cwe_count: int        # M4 contribution
    latency_seconds: float         # M5 contribution
    abstained: bool                # for M6
    ground_truth_irreparable: bool = False    # for M6
    notes: str = ""


# --- aggregators ---


def m1_patch_applicability(obs: Sequence[CaseObservation]) -> float:
    n = len(obs)
    return (sum(1 for o in obs if o.applied) / n) if n else 0.0


def m2_functional_fix_rate(obs: Sequence[CaseObservation]) -> float:
    n = len(obs)
    return (sum(1 for o in obs if o.applied and o.functional_pass) / n) if n else 0.0


def m3_semantic_equivalence(obs: Sequence[CaseObservation]) -> float:
    """Among cases the tool *did* patch, what fraction were behaviorally
    equivalent to the ground-truth fix on benign inputs?"""
    applied = [o for o in obs if o.applied]
    if not applied:
        return 0.0
    return sum(1 for o in applied if o.benign_equivalent) / len(applied)


def m4_residual_cwe_density(obs: Sequence[CaseObservation]) -> float:
    """Total residual sinks per 1k patched lines (corpus-level density).
    The harness records raw counts; we report the mean here."""
    applied = [o for o in obs if o.applied]
    if not applied:
        return 0.0
    return statistics.fmean(o.residual_cwe_count for o in applied)


def m5_median_latency(obs: Sequence[CaseObservation]) -> float:
    return statistics.median(o.latency_seconds for o in obs) if obs else 0.0


def m6_abstention_precision(obs: Sequence[CaseObservation]) -> float:
    """P(ground_truth_irreparable | tool abstained)."""
    abst = [o for o in obs if o.abstained]
    if not abst:
        return 1.0   # vacuously precise -- the tool never abstained
    return sum(1 for o in abst if o.ground_truth_irreparable) / len(abst)


def six_metrics(obs: Sequence[CaseObservation]) -> dict:
    return {
        "M1_patch_applicability":   round(m1_patch_applicability(obs), 4),
        "M2_functional_fix_rate":   round(m2_functional_fix_rate(obs), 4),
        "M3_semantic_equivalence":  round(m3_semantic_equivalence(obs), 4),
        "M4_residual_cwe_mean":     round(m4_residual_cwe_density(obs), 4),
        "M5_median_latency_sec":    round(m5_median_latency(obs), 4),
        "M6_abstention_precision":  round(m6_abstention_precision(obs), 4),
        "n_observations":           len(obs),
    }


# --- supporting helpers ---


_SINK_RE = {
    "java":   re.compile(r"\b(executeQuery|executeUpdate|execute)\s*\(\s*[\"`]"
                         r"[^\"`]*[\"`]\s*\+"),
    "python": re.compile(r"\.\s*(execute|executemany|query|search|xpath)"
                         r"\s*\(\s*(?:f?[\"'][^\"']*\{|.*\+)"),
    "jsts":   re.compile(r"\.\s*(query|execute|all|get|run)\s*\("
                         r"\s*(?:`[^`]*\$\{|[\"'][^\"']*[\"']\s*\+)"),
}


def residual_cwe_count(src: str, language: str) -> int:
    pat = _SINK_RE.get(language)
    if pat is None:
        return 0
    # tighten false positives: the LDAP/XPath safe idiom
    # ``escape_filter_chars(x) + "..."`` or ``$var`` binding is not a
    # residual concat sink even though the regex would otherwise match.
    safe_idioms = ("escape_filter_chars(", "escape_dn_chars(",
                   "$v_", "?, (", "?, [")
    hits = 0
    for m in pat.finditer(src):
        window = src[max(0, m.start() - 40):m.end() + 40]
        if any(s in window for s in safe_idioms):
            continue
        hits += 1
    return hits


def token_jaccard(a: str, b: str) -> float:
    A = set(re.findall(r"[A-Za-z_]\w*|\?|[(),;=*]", a))
    B = set(re.findall(r"[A-Za-z_]\w*|\?|[(),;=*]", b))
    if not A and not B:
        return 1.0
    return len(A & B) / max(len(A | B), 1)


def benign_equivalent_text(patched: str, ground_truth: str,
                           *, jaccard_threshold: float = 0.55) -> bool:
    """Cheap text-level surrogate for M3 when the language/interpreter
    cannot be executed in-process. The harness prefers row-set equality
    via the differential oracle and falls back to this only when neither
    side is executable.
    """
    return token_jaccard(patched, ground_truth) >= jaccard_threshold


# --- timing helper ---


class Stopwatch:
    """Tiny context manager so adapters can record latency uniformly."""

    def __enter__(self):
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, *a):
        self.elapsed = time.perf_counter() - self.t0


# --- detection metrics (precision / recall / F1) ---
#
# The M1..M6 family above scores *patch quality* on the cases the tool
# was asked to repair. A separate, standard question is how well the
# Stage-A detector localises the injection sinks in the first place,
# evaluated against a labelled ground truth (OWASP Benchmark
# ``expectedresults`` or the Juliet good/bad split). For that we use the
# usual confusion-matrix derived scores.


@dataclass(frozen=True)
class DetectionOutcome:
    """One labelled test item for detection scoring.

    ``case_id``     -- stable identifier (file or test name).
    ``is_vulnerable`` -- ground-truth label (True == a real sink exists).
    ``flagged``     -- the tool reported >= 1 in-scope finding.
    """

    case_id: str
    is_vulnerable: bool
    flagged: bool


@dataclass(frozen=True)
class ConfusionMatrix:
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        """FP / (FP + TN) -- the fraction of benign items wrongly flagged."""
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    @property
    def false_negative_rate(self) -> float:
        """FN / (FN + TP) -- the fraction of real sinks missed."""
        denom = self.fn + self.tp
        return self.fn / denom if denom else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.n if self.n else 0.0


def confusion_matrix(outcomes: Sequence[DetectionOutcome]) -> ConfusionMatrix:
    tp = sum(1 for o in outcomes if o.is_vulnerable and o.flagged)
    fn = sum(1 for o in outcomes if o.is_vulnerable and not o.flagged)
    fp = sum(1 for o in outcomes if not o.is_vulnerable and o.flagged)
    tn = sum(1 for o in outcomes if not o.is_vulnerable and not o.flagged)
    return ConfusionMatrix(tp=tp, fp=fp, tn=tn, fn=fn)


def detection_metrics(outcomes: Sequence[DetectionOutcome]) -> dict:
    """Precision, recall, F1 and the FP/FN rates for a labelled corpus."""
    cm = confusion_matrix(outcomes)
    return {
        "precision":           round(cm.precision, 4),
        "recall":              round(cm.recall, 4),
        "f1":                  round(cm.f1, 4),
        "false_positive_rate": round(cm.false_positive_rate, 4),
        "false_negative_rate": round(cm.false_negative_rate, 4),
        "accuracy":            round(cm.accuracy, 4),
        "tp": cm.tp, "fp": cm.fp, "tn": cm.tn, "fn": cm.fn,
        "n": cm.n,
    }
