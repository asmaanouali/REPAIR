"""Tests for the Phase 9 honesty surface."""

from __future__ import annotations

from core.api.honesty import (
    AXIOMATIZED_OBLIGATIONS,
    PROOF_STATUSES,
    GateLike,
    compute_proof_status,
)


def _gates(*pairs) -> tuple[GateLike, ...]:
    return tuple(GateLike(name=n, passed=p, detail="") for n, p in pairs)


def test_taxonomy_is_locked():
    assert PROOF_STATUSES == (
        "proven", "axiomatized", "validated_only", "unverified", "best_effort",
    )


def test_best_effort_when_no_patch():
    status, claim = compute_proof_status(
        stage_reached="C",
        patched=False,
        gates=(),
    )
    assert status == "best_effort"
    assert "best-effort" in claim


def test_best_effort_when_abstention_marker():
    status, claim = compute_proof_status(
        stage_reached="G",
        patched=True,
        gates=_gates(("compile", True)),
        abstention_reason="best_effort:no_binder",
    )
    assert status == "best_effort"


def test_unverified_when_a_gate_fails():
    status, claim = compute_proof_status(
        stage_reached="G",
        patched=True,
        gates=_gates(("compile", True), ("regression", False)),
        proof_obligations=("Lemma 1 (Parameter inertness).",),
    )
    assert status == "unverified"
    assert "regression" in claim


def test_validated_only_when_no_obligation():
    status, claim = compute_proof_status(
        stage_reached="G",
        patched=True,
        gates=_gates(
            ("compile", True), ("regression", True),
            ("structural", True), ("re_sast", True),
            ("differential", True),
        ),
        proof_obligations=(),
    )
    assert status == "validated_only"
    assert "no formal proof obligation" in claim


def test_axiomatized_when_lemma1_present():
    """Lemma 1 (parameter inertness) is currently a Lean axiom."""
    status, claim = compute_proof_status(
        stage_reached="G",
        patched=True,
        gates=_gates(
            ("compile", True), ("regression", True),
            ("structural", True), ("re_sast", True),
            ("differential", True),
        ),
        proof_obligations=("Lemma 1 (Parameter inertness).",),
    )
    assert status == "axiomatized"
    assert "provably safe within assumptions §A.1" in claim
    assert "parameter inertness" in claim.lower()


def test_proven_when_only_lemma2_present():
    """Lemma 2 (identifier-allowlist closure) is a theorem."""
    status, claim = compute_proof_status(
        stage_reached="G",
        patched=True,
        gates=_gates(
            ("compile", True), ("regression", True),
            ("structural", True), ("re_sast", True),
            ("differential", True),
        ),
        proof_obligations=("Lemma 2 (Identifier allow-list closure).",),
    )
    assert status == "proven"
    assert "provably safe within assumptions §A.2" in claim


def test_mixed_obligations_downgrade_to_axiomatized():
    status, _ = compute_proof_status(
        stage_reached="G",
        patched=True,
        gates=_gates(
            ("compile", True), ("regression", True),
            ("structural", True), ("re_sast", True),
            ("differential", True),
        ),
        proof_obligations=(
            "Lemma 1 (Parameter inertness).",
            "Lemma 2 (Identifier allow-list closure).",
        ),
    )
    assert status == "axiomatized"


def test_unknown_obligation_is_conservative():
    status, claim = compute_proof_status(
        stage_reached="G",
        patched=True,
        gates=_gates(
            ("compile", True), ("regression", True),
            ("structural", True), ("re_sast", True),
            ("differential", True),
        ),
        proof_obligations=("Lemma 9 (Made-up theorem).",),
    )
    assert status == "axiomatized"
    assert "Lemma 9" in claim


def test_axiomatized_obligations_set_nonempty():
    assert "Lemma 1 (Parameter inertness)." in AXIOMATIZED_OBLIGATIONS


def test_patch_record_carries_proof_status():
    """Smoke: PatchRecord defaults are sensible."""
    from core.api.facade import PatchRecord
    pr = PatchRecord(
        file="x.java", stage_reached="A", patched=False,
        all_gates_passed=False, abstention_reason="no_sink_found",
        unified_diff=None, patched_source=None, prepared_template=None,
        binders_used=[], gates=[],
    )
    assert pr.proof_status == "unverified"
    assert pr.safety_claim == ""


def test_no_bare_provably_safe_in_repo():
    """CI grep guard: the literal phrase 'provably safe' must never
    appear outside core/api/honesty.py (which contains the
    qualified template) or test files.
    """
    import os
    from pathlib import Path

    ROOT = Path(__file__).resolve().parents[1]
    offenders: list[str] = []
    allow_files = {
        ROOT / "core" / "api" / "honesty.py",
    }
    for dirpath, _, filenames in os.walk(ROOT):
        # Skip generated / vendor folders.
        if any(seg in dirpath for seg in (
            ".venv", "__pycache__", ".hypothesis", "htmlcov",
            "reports", ".git",
        )):
            continue
        for fn in filenames:
            if not fn.endswith((".py", ".md", ".yaml", ".yml", ".tex")):
                continue
            p = Path(dirpath) / fn
            if p in allow_files:
                continue
            # Tests may quote the phrase.
            if p.name.startswith("test_"):
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                low = line.lower()
                if "provably safe" in low and "within assumptions" not in low:
                    offenders.append(f"{p}:{i}:{line.strip()[:160]}")

    # Allow a small grandfathered set in legacy docs/paper drafts.
    # Anything new must be qualified.
    grandfather_substrings = (
        # Markdown headings and historical release notes can stay
        # as long as the prose immediately qualifies them; we only
        # block unqualified inline claims.
    )
    filtered = [o for o in offenders
                if not any(s in o for s in grandfather_substrings)]
    assert not filtered, (
        "Unqualified 'provably safe' occurrences found:\n  "
        + "\n  ".join(filtered[:20])
    )
