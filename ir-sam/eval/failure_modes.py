"""Top-10 failure-mode catalog generator (Phase 5).

Reads the per-case observations from the Phase-5 orchestrator and
distills the abstention / fix-failure reasons into a ranked catalog
of at-most ten categories. Each category aggregates the raw notes
emitted by the baselines + IR-SAM and reports:

  * frequency (count)
  * % of all observations affected
  * the dominant tool exhibiting it
  * one or two illustrative ``case_id`` exemplars
  * suggested remediation owner (slicer / parser / binder / oracle /
    documentation / out-of-scope)

The intent is to provide reviewers with a concrete artifact for §6.4
of the Phase-5 paper.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence


# Each rule is (label, pattern, owner, remediation_hint). The order
# matters: the first match wins so that more specific rules fire
# before catch-alls.
_RULES: list[tuple[str, re.Pattern, str, str]] = [
    ("non_string_concat",      re.compile(r"non[-_ ]string[-_ ]?concat",
                                           re.I),
     "slicer", "handle StringBuilder / fmt.Sprintf concatenation"),
    ("escaped_quote",          re.compile(r"escaped[-_ ]quote", re.I),
     "slicer", "track escape sequences inside literal segments"),
    ("escapes_method",         re.compile(r"escapes?_method", re.I),
     "slicer", "support cross-method def-use chains"),
    ("no_static_skeleton",     re.compile(r"recon:|no_static_skeleton"),
     "slicer", "extend backward-slicer to follow one helper hop"),
    ("sql0_ambiguous_intent",  re.compile(r"parse:SQL0AmbiguousIntent|"
                                            r"ambiguous_intent"),
     "parser", "expand SQL\u2080 grammar coverage"),
    ("sql0_syntax_error",      re.compile(r"parse:SQL0SyntaxError|"
                                            r"sql0_syntax"),
     "parser", "tighten template inference + escape tracking"),
    ("ldap_syntax",            re.compile(r"parse:LDAPSyntax"),
     "parser", "broaden RFC-4515 subset"),
    ("xpath_syntax",           re.compile(r"parse:XPathSyntax"),
     "parser", "expand XPath 1.0 subset"),
    ("missing_allowlist",      re.compile(r"binder:.*allowlist|"
                                            r"allowlist_missing"),
     "binder", "ship a default identifier allowlist per project"),
    ("interproc_unsupported",  re.compile(r"interproc|cross[-_ ]file|"
                                            r"cross[-_ ]method"),
     "slicer", "Phase-6 IPA pass"),
    ("oracle_disagreement",    re.compile(r"oracle:|row_set_mismatch"),
     "oracle", "tighten benign-fixture equivalence rules"),
    ("rewrite_arity",          re.compile(r"rewrite:.*arity|ldap_arity"),
     "rewriter", "track argument arity per sink API"),
    ("llm_hallucinated_api",   re.compile(r"hallucinat|non-existent API|"
                                            r"unparseable"),
     "out-of-scope", "LLM baselines only -- not a defect of IR-SAM"),
    ("model_gen_failure",      re.compile(r"loop exhausted|invalid translation|"
                                            r"incorrect token"),
     "out-of-scope", "LLM/seq2seq baselines"),
    ("latency_budget_exceeded", re.compile(r"timeout|deadline_exceeded"),
     "infrastructure", "raise per-case wall-clock budget"),
]


@dataclass
class FailureMode:
    rank: int
    label: str
    owner: str
    remediation: str
    count: int
    pct_of_observations: float
    dominant_tool: str
    exemplars: list[str] = field(default_factory=list)


def classify(note: str) -> str:
    if not note:
        return "uncategorized"
    for label, rx, _, _ in _RULES:
        if rx.search(note):
            return label
    return "uncategorized"


def build_catalog(records: Sequence[dict], *, top_k: int = 10
                  ) -> list[FailureMode]:
    """``records`` is a list of per-(case, tool) dicts with keys
    ``tool``, ``case_id``, ``notes``, ``applied``, ``functional_pass``.
    Only records that did NOT functionally fix the case count as
    failure modes (abstentions + wrong patches both).
    """
    failures = [r for r in records if not r.get("functional_pass")]
    total = len(records) or 1
    bucket_counts: Counter = Counter()
    bucket_tools: dict[str, Counter] = defaultdict(Counter)
    bucket_examples: dict[str, list[str]] = defaultdict(list)
    for r in failures:
        lab = classify(str(r.get("notes", "")))
        bucket_counts[lab] += 1
        bucket_tools[lab][r.get("tool", "?")] += 1
        if len(bucket_examples[lab]) < 2:
            bucket_examples[lab].append(r.get("case_id", "?"))

    rules_by_label = {label: (owner, rem) for label, _, owner, rem in _RULES}
    out: list[FailureMode] = []
    for i, (lab, cnt) in enumerate(bucket_counts.most_common(top_k), start=1):
        owner, rem = rules_by_label.get(lab, ("triage", "investigate"))
        dom_tool, _ = bucket_tools[lab].most_common(1)[0]
        out.append(FailureMode(
            rank=i, label=lab, owner=owner, remediation=rem,
            count=cnt,
            pct_of_observations=round(100 * cnt / total, 2),
            dominant_tool=dom_tool,
            exemplars=list(bucket_examples[lab]),
        ))
    return out


def write_catalog(catalog: list[FailureMode], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "phase5_failure_modes.json"
    md_path = out_dir / "phase5_failure_modes.md"
    json_path.write_text(json.dumps(
        [fm.__dict__ for fm in catalog], indent=2), encoding="utf-8")
    lines = ["# Phase 5 -- Top-10 failure-mode catalog",
             "",
             "| Rank | Label | Owner | Count | % obs | Dominant tool | "
             "Exemplars | Remediation |",
             "|---:|---|---|---:|---:|---|---|---|"]
    for fm in catalog:
        lines.append(
            f"| {fm.rank} | `{fm.label}` | {fm.owner} | {fm.count} | "
            f"{fm.pct_of_observations}% | {fm.dominant_tool} | "
            f"{', '.join(fm.exemplars)} | {fm.remediation} |")
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
