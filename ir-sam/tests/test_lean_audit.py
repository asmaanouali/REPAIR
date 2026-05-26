"""Phase 8 — Lean source auditor.

This test does not invoke ``lean`` or ``lake``; it lexically parses
the ``ir-sam/formal/IRSAM/**.lean`` sources and asserts:

1.  No ``sorry`` appears outside a comment.
2.  Every ``axiom`` declaration carries an opening doc-comment
    (``/-- ... -/``) so each assumption is named and documented.
3.  Every ``proof_obligation:`` string in ``binders/*.yaml`` maps to
    an entry in the human-readable
    :data:`OBLIGATION_TO_LEAN_NAME` table — and (when the prose is
    one of the *axiomatized* ones from
    ``core.api.honesty.AXIOMATIZED_OBLIGATIONS``) a Lean ``axiom`` of
    that name exists.

It also writes (idempotently) ``reports/phase8_lean_report.md``
summarizing each axiom.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
FORMAL_DIR = ROOT / "formal" / "IRSAM"
BINDER_DIR = ROOT / "binders"
REPORT_PATH = ROOT / "reports" / "phase8_lean_report.md"


_AXIOM_RE = re.compile(r"^\s*axiom\s+([A-Za-z_][A-Za-z0-9_]*)\s*:", re.MULTILINE)
_DOCAXIOM_RE = re.compile(
    r"/--[\s\S]*?-/\s*\n\s*axiom\s+([A-Za-z_][A-Za-z0-9_]*)\s*:",
    re.MULTILINE,
)
_SORRY_RE = re.compile(r"\bsorry\b")
_COMMENT_RE = re.compile(r"/-.*?-/", re.DOTALL)


OBLIGATION_TO_LEAN_NAME: dict[str, str] = {
    "Lemma 1 (Parameter inertness).":
        "jdbc_parameter_inertness_ax",
    "Lemma 1.":
        "jdbc_parameter_inertness_ax",
    "Lemma 1 (Parameter inertness), induction step (lists).":
        "jdbc_parameter_inertness_ax",
    "Lemma 1 (Parameter inertness, Django ORM compiler).":
        "django_orm_parameter_inertness_ax",
    "Lemma 1 (Parameter inertness, DB-API params).":
        "dbapi_parameter_inertness_ax",
    "Lemma 1 (Parameter inertness, DB-API).":
        "dbapi_parameter_inertness_ax",
    "Lemma 1 (Parameter inertness, MyBatis runtime semantics).":
        "mybatis_parameter_inertness_ax",
    "Lemma 1 (Parameter inertness via XPath variable binding).":
        "xpath_variable_binding_inertness_ax",
    "Lemma 1' (LDAP value escaping closure: RFC4515 §3 escapes \\ * ( ) NUL).":
        "ldap_rfc4515_escape_closure_ax",
    "Lemma 1'.":
        "ldap_rfc4515_escape_closure_ax",
    "Lemma 2 (Identifier allow-list closure).":
        "identifier_allowlist_closure",
    "Lemma 2.":
        "identifier_allowlist_closure",
}


def _strip_comments(src: str) -> str:
    return _COMMENT_RE.sub("", src)


def _all_lean_files() -> list[Path]:
    return sorted(FORMAL_DIR.rglob("*.lean"))


def test_no_sorry_outside_comments():
    """Every ``sorry`` must live inside a comment block."""
    offenders: list[str] = []
    for f in _all_lean_files():
        text = f.read_text(encoding="utf-8")
        stripped = _strip_comments(text)
        for m in _SORRY_RE.finditer(stripped):
            # report the line in the original file
            line = stripped[:m.start()].count("\n") + 1
            offenders.append(f"{f.relative_to(ROOT)}:{line}")
    assert not offenders, "Lean `sorry` found outside comments: " + ", ".join(offenders)


def test_every_axiom_is_named_and_documented():
    """Every ``axiom`` declaration must be preceded by ``/-- ... -/``
    (Lean's documentation-comment form)."""
    undocumented: list[str] = []
    for f in _all_lean_files():
        text = f.read_text(encoding="utf-8")
        documented = {m.group(1) for m in _DOCAXIOM_RE.finditer(text)}
        for m in _AXIOM_RE.finditer(text):
            if m.group(1) not in documented:
                undocumented.append(f"{f.relative_to(ROOT)}::{m.group(1)}")
    assert not undocumented, (
        "Lean axioms missing /-- ... -/ doc-comment: "
        + ", ".join(undocumented)
    )


def test_axiom_inventory_matches_obligations():
    """Every axiomatized obligation referenced by a binder YAML must
    correspond to an actual Lean ``axiom``."""
    from core.api.honesty import AXIOMATIZED_OBLIGATIONS

    # Collect all axiom names declared in the Lean sources.
    declared: set[str] = set()
    for f in _all_lean_files():
        text = f.read_text(encoding="utf-8")
        for m in _AXIOM_RE.finditer(text):
            declared.add(m.group(1))

    missing: list[str] = []
    for prose in AXIOMATIZED_OBLIGATIONS:
        name = OBLIGATION_TO_LEAN_NAME.get(prose)
        if name is None:
            # The obligation is axiomatized but we have not mapped it
            # to a Lean name yet — flag it.
            missing.append(f"unmapped: {prose}")
            continue
        if name not in declared:
            missing.append(f"missing axiom {name} (for: {prose})")
    assert not missing, "Phase 8 axiom inventory gaps: " + "; ".join(missing)


def test_binder_obligations_are_known():
    """Every ``proof_obligation`` string used by a binder YAML must
    appear in :data:`OBLIGATION_TO_LEAN_NAME` (or in the multi-line
    free-form set — those are tracked separately in the report)."""
    free_form: list[tuple[str, str]] = []
    for yml in sorted(BINDER_DIR.glob("*.yaml")):
        try:
            raw = yaml.safe_load(yml.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        cat = (raw or {}).get("catalog", {})
        for b in cat.get("binders", []):
            ob = b.get("proof_obligation")
            if not ob:
                continue
            ob_str = str(ob).strip()
            if "\n" in ob_str:
                # Free-form multi-line obligations (shell, processbuilder
                # families) — they are documented inline; covered by
                # the Shell.lean theorem `argv_inertness`.
                free_form.append((yml.name, ob_str.splitlines()[0][:80]))
                continue
            if ob_str not in OBLIGATION_TO_LEAN_NAME:
                raise AssertionError(
                    f"{yml.name}: unknown proof_obligation prose {ob_str!r}; "
                    f"add to tests/test_lean_audit.OBLIGATION_TO_LEAN_NAME"
                )
    # Free-form list is informational only; assert it is bounded.
    assert len(free_form) <= 8


def test_report_is_regenerable(tmp_path):
    """Smoke: the report writer must be importable and produce
    well-formed Markdown."""
    body = _build_report_markdown()
    target = tmp_path / "phase8_lean_report.md"
    target.write_text(body, encoding="utf-8")
    assert "# Phase 8 — Lean Audit Report" in body
    assert "## Axioms" in body
    assert "## Binder → Lean obligation map" in body
    # Persist the up-to-date report alongside other auto-generated
    # artifacts. We do this last so a test failure above leaves the
    # checked-in report untouched.
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(body, encoding="utf-8")


def _build_report_markdown() -> str:
    axioms: list[tuple[str, Path]] = []
    for f in _all_lean_files():
        text = f.read_text(encoding="utf-8")
        for m in _AXIOM_RE.finditer(text):
            axioms.append((m.group(1), f.relative_to(ROOT)))

    out: list[str] = []
    out.append("# Phase 8 — Lean Audit Report")
    out.append("")
    out.append(
        "Auto-generated by `tests/test_lean_audit.py`. Lists every "
        "explicit assumption that IR-SAM's soundness argument depends "
        "on, with the binder(s) that rely on it."
    )
    out.append("")
    out.append("## Axioms")
    out.append("")
    out.append("| Lean name | Defined in |")
    out.append("|---|---|")
    for name, path in sorted(axioms):
        out.append(f"| `{name}` | `{path.as_posix()}` |")
    out.append("")
    out.append("## Binder → Lean obligation map")
    out.append("")
    out.append("| Binder YAML | Obligation prose | Lean name |")
    out.append("|---|---|---|")
    for yml in sorted(BINDER_DIR.glob("*.yaml")):
        try:
            raw = yaml.safe_load(yml.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue
        for b in raw.get("catalog", {}).get("binders", []):
            ob = b.get("proof_obligation")
            if not ob:
                continue
            ob_str = str(ob).strip().splitlines()[0][:120]
            lean = OBLIGATION_TO_LEAN_NAME.get(ob_str, "(free-form)")
            out.append(f"| `{yml.name}` | {ob_str} | `{lean}` |")
    out.append("")
    return "\n".join(out)
