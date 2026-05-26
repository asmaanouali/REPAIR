"""Phase 9 — honesty surface.

Computes ``PatchRecord.proof_status`` and ``PatchRecord.safety_claim``
from pipeline artifacts. The intent is that the only string the
product ever shows next to a patch comes from
:func:`format_safety_claim` and is always qualified by the underlying
assumption set, so the previous bare phrase "provably safe" never
appears unqualified again.

Status taxonomy
===============

``proven``
    All five gates green, and the binder's ``proof_obligation``
    references a Lean *theorem* (no ``axiom`` on the path).

``axiomatized``
    All five gates green, but the binder's ``proof_obligation``
    references at least one named Lean ``axiom``. The patch is safe
    *modulo* those assumptions (e.g. JDBC PreparedStatement
    inertness as documented in §A.2).

``validated_only``
    All five gates green, but the binder declares no
    ``proof_obligation``. We have empirical evidence (compile +
    differential + re-SAST + structural + regression) but no formal
    invariant.

``unverified``
    At least one gate failed or was soft-failed (e.g.
    ``TEST_REGRESSION_NOT_CONFIGURED``). The patched code might be
    correct; the validator has not proven it so.

``best_effort``
    The pipeline abstained from synthesizing executable code and
    emitted a commented review hint only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


PROOF_STATUSES = (
    "proven",
    "axiomatized",
    "validated_only",
    "unverified",
    "best_effort",
)


# Per-status human-readable templates. The product (CLI, UI, JSON)
# MUST format final user-facing claims through this dict; CI grep
# guards against any other "provably safe" string.
_CLAIM_TEMPLATES: dict[str, str] = {
    "proven":         "provably safe within assumptions §A.{section} ({assumptions})",
    "axiomatized":    "provably safe within assumptions §A.{section} ({assumptions})",
    "validated_only": "validated by gate ensemble; no formal proof obligation declared",
    "unverified":     "unverified: {reason}",
    "best_effort":    "best-effort review hint; no executable change applied",
}


# Mapping from a binder's proof_obligation prose to the assumption
# section in docs/assumptions.md (Phase 9 deliverable). Keep prose
# stable: changing a binder string requires updating this table.
_OBLIGATION_TO_SECTION: dict[str, tuple[str, str]] = {
    "Lemma 1 (Parameter inertness).":
        ("1", "parameter inertness for the host driver"),
    "Lemma 1.":
        ("1", "parameter inertness for the host driver"),
    "Lemma 1 (Parameter inertness), induction step (lists).":
        ("1", "parameter inertness, induction step over lists"),
    "Lemma 1 (Parameter inertness, Django ORM compiler).":
        ("1", "Django ORM SQL compiler parameter inertness"),
    "Lemma 1 (Parameter inertness, DB-API params).":
        ("1", "DB-API parameterized query inertness"),
    "Lemma 1 (Parameter inertness, DB-API).":
        ("1", "DB-API parameterized query inertness"),
    "Lemma 1 (Parameter inertness, MyBatis runtime semantics).":
        ("1", "MyBatis runtime parameter inertness"),
    "Lemma 2 (Identifier allow-list closure).":
        ("2", "identifier-allowlist closure"),
    "Lemma 2.":
        ("2", "identifier-allowlist closure"),
    "Lemma 1 (Parameter inertness via XPath variable binding).":
        ("1", "XPath variable-binding inertness"),
    "Lemma 1' (LDAP value escaping closure: RFC4515 §3 escapes \\ * ( ) NUL).":
        ("1", "LDAP RFC4515 §3 value-escape closure"),
    "Lemma 1'.":
        ("1", "LDAP RFC4515 §3 value-escape closure"),
}


# Set of obligations that today reduce to a Lean ``axiom`` rather
# than a fully-discharged theorem. These are honest about what is
# assumed vs. proven. Phase 8 may move entries out of this set as
# theorems mature.
AXIOMATIZED_OBLIGATIONS: frozenset[str] = frozenset({
    "Lemma 1 (Parameter inertness).",
    "Lemma 1.",
    "Lemma 1 (Parameter inertness), induction step (lists).",
    "Lemma 1 (Parameter inertness, Django ORM compiler).",
    "Lemma 1 (Parameter inertness, DB-API params).",
    "Lemma 1 (Parameter inertness, DB-API).",
    "Lemma 1 (Parameter inertness, MyBatis runtime semantics).",
    "Lemma 1 (Parameter inertness via XPath variable binding).",
    "Lemma 1' (LDAP value escaping closure: RFC4515 §3 escapes \\ * ( ) NUL).",
    "Lemma 1'.",
})


@dataclass(frozen=True)
class GateLike:
    """Light protocol surface so this module does not depend on the
    validator's heavy ``GateOutcome`` import.
    """

    name: str
    passed: bool
    detail: str = ""


def compute_proof_status(
    *,
    stage_reached: str,
    patched: bool,
    gates: Iterable[GateLike],
    proof_obligations: Iterable[str] = (),
    abstention_reason: str | None = None,
) -> tuple[str, str]:
    """Compute ``(proof_status, safety_claim)`` for a patch.

    Parameters
    ----------
    stage_reached
        Pipeline stage that was last completed (``"A"``-``"G"``).
    patched
        Whether a unified diff was emitted (executable change vs.
        commented hint).
    gates
        Iterable of gate outcomes.
    proof_obligations
        The ``proof_obligation`` strings collected from every
        binder used to construct the patch. Empty when no binder
        carries a formal obligation.
    abstention_reason
        Pipeline-level abstention reason if any.
    """
    # Best-effort short-circuit.
    if abstention_reason and abstention_reason.startswith("best_effort"):
        return ("best_effort", _CLAIM_TEMPLATES["best_effort"])
    if not patched:
        return ("best_effort", _CLAIM_TEMPLATES["best_effort"])

    gates_tuple = tuple(gates)
    failing = [g for g in gates_tuple if not g.passed]
    if failing:
        reason = "; ".join(
            f"{g.name}({g.detail.splitlines()[0][:80] if g.detail else 'failed'})"
            for g in failing
        )
        return (
            "unverified",
            _CLAIM_TEMPLATES["unverified"].format(reason=reason),
        )

    obligations = tuple(o for o in proof_obligations if o)
    if not obligations:
        return ("validated_only", _CLAIM_TEMPLATES["validated_only"])

    sections: list[str] = []
    assumptions: list[str] = []
    has_axiom = False
    for o in obligations:
        entry = _OBLIGATION_TO_SECTION.get(o)
        if entry is None:
            # Unknown obligation prose → be conservative; treat as
            # axiomatized so we do not over-claim.
            has_axiom = True
            sections.append("?")
            assumptions.append(o.rstrip("."))
            continue
        section, label = entry
        sections.append(section)
        assumptions.append(label)
        if o in AXIOMATIZED_OBLIGATIONS:
            has_axiom = True

    status = "axiomatized" if has_axiom else "proven"
    claim = _CLAIM_TEMPLATES[status].format(
        section="/".join(sorted(set(sections))),
        assumptions=", ".join(sorted(set(assumptions))),
    )
    return (status, claim)


__all__ = [
    "AXIOMATIZED_OBLIGATIONS",
    "PROOF_STATUSES",
    "GateLike",
    "compute_proof_status",
]
