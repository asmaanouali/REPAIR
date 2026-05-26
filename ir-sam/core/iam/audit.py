"""Mechanized soundness-audit checker.

Given a ``(pre, patch, post)`` triple this module verifies the four
soundness predicates from :doc:`docs/soundness-proof.md` §4:

    P1 -- syntactic well-formedness of the patched program.
    P2 -- semantic-type preservation across host expressions.
    P3 -- hole coverage: every hole in the IAM is realized in the host AST
          via either a parameterized-API call or an allow-list lookup.
    P4 -- interpreter-equivalence on benign inputs: the pre- and post-patch
          oracle templates yield the same row/entry/node set on benign
          payloads.

The check is *structural*: P1/P2/P3 are decided over the IAM + the list
of :class:`HostRealization` records that stage E emits; P4 is decided
over the differential-oracle output for a fixed benign payload set.

The output is a :class:`AuditReport` with a per-predicate verdict and a
list of counterexamples suitable for serialization to
``reports/soundness/<run-id>/counterexamples/``.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Sequence

from core.iam import HostRealization, IAM, SyntCtx, structurally_sound


@dataclass(frozen=True)
class Predicate:
    name: str  # "P1" | "P2" | "P3" | "P4"
    passed: bool
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuditReport:
    case_id: str
    predicates: tuple[Predicate, ...]
    counterexamples: tuple[dict, ...] = ()

    @property
    def overall_passed(self) -> bool:
        return all(p.passed for p in self.predicates)

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)

    def by_name(self, name: str) -> Predicate | None:
        for p in self.predicates:
            if p.name == name:
                return p
        return None


# --- P1: syntactic well-formedness -------------------------------------------


def _p1_well_formed(post_source: str, language: str) -> Predicate:
    reasons: list[str] = []
    if language == "java":
        if post_source.count("{") != post_source.count("}"):
            reasons.append("unbalanced braces in patched Java source")
        if post_source.count("(") != post_source.count(")"):
            reasons.append("unbalanced parentheses in patched Java source")
        if "executeQuery(\"" in post_source and "\" +" in post_source.split(
            "executeQuery(\"", 1
        )[1].split(")", 1)[0]:
            reasons.append("residual string-concat in executeQuery argument")
    return Predicate("P1", not reasons, tuple(reasons))


# --- P2: semantic-type preservation ------------------------------------------


_SETTER_FOR_SEM = {
    "string": {"java.sql.PreparedStatement.setString",
               "java.sql.PreparedStatement.setObject"},
    "integer": {"java.sql.PreparedStatement.setInt",
                "java.sql.PreparedStatement.setLong",
                "java.sql.PreparedStatement.setObject"},
    "decimal": {"java.sql.PreparedStatement.setBigDecimal",
                "java.sql.PreparedStatement.setObject"},
    "boolean": {"java.sql.PreparedStatement.setBoolean",
                "java.sql.PreparedStatement.setObject"},
    "date": {"java.sql.PreparedStatement.setDate",
             "java.sql.PreparedStatement.setTimestamp",
             "java.sql.PreparedStatement.setObject"},
    "blob": {"java.sql.PreparedStatement.setBytes",
             "java.sql.PreparedStatement.setObject"},
}


def _p2_types_preserved(iam: IAM,
                        realizations: Sequence[HostRealization]) -> Predicate:
    reasons: list[str] = []
    by_name = {r.hole_name: r for r in realizations}
    for h in iam.holes:
        if h.ctx is not SyntCtx.VALUE:
            continue
        r = by_name.get(h.name)
        if r is None or r.via != "parameterized-api" or r.api is None:
            continue  # P3 will catch this
        permitted = _SETTER_FOR_SEM.get(h.sem.value, set())
        if permitted and r.api not in permitted:
            reasons.append(
                f"hole {h.name!r} of SemType {h.sem.value!r} bound via "
                f"{r.api!r}, which does not preserve the semantic type"
            )
    return Predicate("P2", not reasons, tuple(reasons))


# --- P3: hole coverage -------------------------------------------------------


def _p3_hole_coverage(iam: IAM,
                      realizations: Sequence[HostRealization],
                      parameterizing_apis: set[str]) -> Predicate:
    ok, reasons = structurally_sound(iam, realizations, parameterizing_apis)
    return Predicate("P3", ok, tuple(reasons))


# --- P4: interpreter-equivalence on benign inputs ----------------------------


@dataclass(frozen=True)
class OracleOutcome:
    """Result of one (pre, post, payload) probe."""
    payload: str
    pre_rowset: tuple
    post_rowset: tuple

    @property
    def equivalent(self) -> bool:
        return self.pre_rowset == self.post_rowset


def _p4_interpreter_equivalence(oracle_outcomes: Sequence[OracleOutcome]
                                ) -> Predicate:
    reasons: list[str] = []
    for o in oracle_outcomes:
        if not o.equivalent:
            reasons.append(
                f"benign payload {o.payload!r}: pre={o.pre_rowset!r} "
                f"!= post={o.post_rowset!r}"
            )
    return Predicate("P4", not reasons, tuple(reasons))


# --- public entrypoint -------------------------------------------------------


def audit(
    *,
    case_id: str,
    iam: IAM,
    realizations: Sequence[HostRealization],
    parameterizing_apis: set[str],
    patched_source: str,
    language: str = "java",
    oracle_outcomes: Sequence[OracleOutcome] = (),
) -> AuditReport:
    """Run the four predicates and return a structured verdict."""
    preds = (
        _p1_well_formed(patched_source, language),
        _p2_types_preserved(iam, realizations),
        _p3_hole_coverage(iam, realizations, parameterizing_apis),
        _p4_interpreter_equivalence(oracle_outcomes),
    )
    counterexamples: list[dict] = []
    for p in preds:
        for r in p.reasons:
            counterexamples.append({"predicate": p.name, "reason": r,
                                    "case_id": case_id})
    return AuditReport(case_id=case_id, predicates=preds,
                       counterexamples=tuple(counterexamples))


def write_report(report: AuditReport, root: Path) -> Path:
    """Persist the report under ``root/<case_id>.json``; counterexamples too."""
    root.mkdir(parents=True, exist_ok=True)
    out = root / f"{report.case_id}.json"
    out.write_text(report.to_json(), encoding="utf-8")
    if report.counterexamples:
        cex_dir = root / "counterexamples"
        cex_dir.mkdir(exist_ok=True)
        (cex_dir / f"{report.case_id}.json").write_text(
            json.dumps(report.counterexamples, indent=2), encoding="utf-8"
        )
    return out
