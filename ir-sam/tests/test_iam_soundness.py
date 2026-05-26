"""Tests for the IAM/SIG structural-soundness predicate."""

from __future__ import annotations

from core.iam import (
    Cardinality,
    Constraint,
    Hole,
    HostRealization,
    IAM,
    Literal,
    SemType,
    SIGNode,
    SymbolEntry,
    SyntCtx,
    structurally_sound,
)

PARAM_APIS = {
    "java.sql.PreparedStatement.setString",
    "java.sql.PreparedStatement.setInt",
}


def _select_eq_iam() -> IAM:
    table_lit = Literal("users")
    col_lit = Literal("email")
    v = Hole("v", SyntCtx.VALUE, SemType.STRING, Cardinality.ONE)
    sig = SIGNode(
        "Select",
        children=(
            SIGNode("TableRef", (table_lit,)),
            SIGNode(
                "Predicate",
                (SIGNode("Comparison", (col_lit, Literal("="), v)),),
            ),
        ),
    )
    return IAM(sig=sig, holes=(v,), constraints=(), symbols=(), interpreter="sql")


def test_value_hole_via_parameterized_api_is_sound() -> None:
    iam = _select_eq_iam()
    r = HostRealization("v", "parameterized-api", "java.sql.PreparedStatement.setString")
    ok, reasons = structurally_sound(iam, [r], PARAM_APIS)
    assert ok, reasons


def test_value_hole_via_string_concat_is_unsound() -> None:
    iam = _select_eq_iam()
    r = HostRealization("v", "literal-in-template")
    ok, reasons = structurally_sound(iam, [r], PARAM_APIS)
    assert not ok
    assert any("not bound via a parameterized API" in r for r in reasons)


def test_identifier_hole_requires_allowlist() -> None:
    c = Hole(
        "c", SyntCtx.IDENTIFIER, SemType.ENUM, Cardinality.ONE,
        allowlist=("id", "email", "created_at"),
    )
    sig = SIGNode("OrderList", (c,))
    iam = IAM(sig=sig, holes=(c,))
    bad = HostRealization("c", "literal-in-template")
    good = HostRealization("c", "allowlist-lookup")
    ok_bad, _ = structurally_sound(iam, [bad], PARAM_APIS)
    ok_good, _ = structurally_sound(iam, [good], PARAM_APIS)
    assert not ok_bad and ok_good


def test_symbol_not_in_DT_makes_it_unsound() -> None:
    iam = _select_eq_iam()
    # Add a tainted symbol
    iam2 = IAM(
        sig=iam.sig, holes=iam.holes,
        symbols=(SymbolEntry("table", "userInput", proven_in_DT=False),),
    )
    r = HostRealization("v", "parameterized-api", "java.sql.PreparedStatement.setString")
    ok, reasons = structurally_sound(iam2, [r], PARAM_APIS)
    assert not ok
    assert any("not proven in D_T" in r for r in reasons)


def test_unrealized_hole_is_unsound() -> None:
    iam = _select_eq_iam()
    ok, reasons = structurally_sound(iam, [], PARAM_APIS)
    assert not ok
    assert any("not realized" in r for r in reasons)


def test_unknown_api_is_rejected() -> None:
    iam = _select_eq_iam()
    r = HostRealization("v", "parameterized-api", "evil.UnsafeApi.exec")
    ok, reasons = structurally_sound(iam, [r], PARAM_APIS)
    assert not ok
    assert any("not in the trusted parameterizing-API set" in r for r in reasons)
