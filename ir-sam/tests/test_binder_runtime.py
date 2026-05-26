"""Tests for :mod:`core.binder.runtime`.

These tests exercise the catalog-driven binder runtime engine
independently of the phi facade. They assert that:

1. Each shipped binder YAML catalog matches at least one synthetic SIG
   subtree whose shape conforms to the binder's declared pattern.
2. ``collect_ops`` produces the right typed :class:`RewriteOp` and
   advances ``param_index`` correctly for value-context holes.
3. The pattern matcher rejects shapes that don't match (kind/ctx/sem
   mismatches).
4. ``resolve_api`` resolves macros from the catalog (``choose_setter``,
   ``choose_ldap_escape``, ``choose_xpath_variable_binding``) and
   returns ``None`` for unknown macros.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.binder.loader import load_catalog
from core.binder.runtime import (
    AllowlistGuardOp,
    InListExpandOp,
    ParamBindOp,
    _RuntimeAbstain,
    collect_ops,
    match_binder,
    match_node,
    resolve_api,
    short_method_for_api,
)
from core.iam import Cardinality, Hole, Literal, SemType, SIGNode, SyntCtx


BINDERS_DIR = Path(__file__).resolve().parents[1] / "binders"


# --- pattern matching --------------------------------------------------------


def _comp_eq(hole_sem: SemType, name: str = "h0") -> SIGNode:
    return SIGNode(
        kind="Comparison",
        children=(
            SIGNode(kind="Column", children=(Literal("name"),)),
            Literal("="),
            Hole(name=name, ctx=SyntCtx.VALUE, sem=hole_sem),
        ),
    )


def _like_expr(name: str = "h0") -> SIGNode:
    return SIGNode(
        kind="LikeExpr",
        children=(
            SIGNode(kind="Column", children=(Literal("title"),)),
            Literal("LIKE"),
            Hole(name=name, ctx=SyntCtx.VALUE, sem=SemType.STRING),
        ),
    )


def _in_expr(name: str = "h0") -> SIGNode:
    return SIGNode(
        kind="InExpr",
        children=(
            SIGNode(kind="Column", children=(Literal("id"),)),
            Literal("IN"),
            Hole(name=name, ctx=SyntCtx.VALUE, sem=SemType.INTEGER,
                 card=Cardinality.MANY_BOUNDED),
        ),
    )


def _orderlist_ident(name: str = "h0") -> SIGNode:
    return SIGNode(
        kind="OrderList",
        children=(
            Hole(name=name, ctx=SyntCtx.IDENTIFIER, sem=SemType.ENUM),
        ),
    )


# --- JDBC catalog ------------------------------------------------------------


@pytest.fixture(scope="module")
def jdbc():
    return load_catalog(BINDERS_DIR / "sql_jdbc.yaml")


def test_match_binder_picks_eq_for_string(jdbc):
    node = _comp_eq(SemType.STRING)
    m = match_binder(jdbc, node)
    assert m is not None
    assert m.binder.id == "sql-eq-value"
    assert "v" in m.bindings
    assert isinstance(m.bindings["v"], Hole)


def test_match_binder_rejects_wrong_kind(jdbc):
    # An OrderList shape must NOT match the eq-value binder pattern.
    m = match_binder(jdbc, _orderlist_ident())
    assert m is not None
    assert m.binder.id == "sql-orderby-ident"


def test_match_node_rejects_ctx_mismatch():
    pattern = {
        "kind": "Hole", "ctx": "value", "sem_in": ["string"], "bind": "v",
    }
    ident_hole = Hole(name="h", ctx=SyntCtx.IDENTIFIER, sem=SemType.STRING)
    assert match_node(pattern, ident_hole) is None


def test_match_node_rejects_sem_mismatch():
    pattern = {"kind": "Hole", "ctx": "value", "sem_in": ["integer"]}
    str_hole = Hole(name="h", ctx=SyntCtx.VALUE, sem=SemType.STRING)
    assert match_node(pattern, str_hole) is None


# --- collect_ops -------------------------------------------------------------


def test_collect_ops_eq_string_emits_param_bind(jdbc):
    node = _comp_eq(SemType.STRING)
    m = match_binder(jdbc, node)
    ops, next_idx = collect_ops(
        m, jdbc, host_exprs={"h0": "userName"}, allowlists={}, param_index=1,
    )
    assert next_idx == 2
    assert len(ops) == 1
    op = ops[0]
    assert isinstance(op, ParamBindOp)
    assert op.api == "java.sql.PreparedStatement.setString"
    assert op.host_expr == "userName"
    assert op.param_index == 1


def test_collect_ops_eq_integer_resolves_to_setLong(jdbc):
    node = _comp_eq(SemType.INTEGER)
    m = match_binder(jdbc, node)
    ops, _ = collect_ops(
        m, jdbc, host_exprs={"h0": "id"}, allowlists={}, param_index=1,
    )
    assert isinstance(ops[0], ParamBindOp)
    assert ops[0].api == "java.sql.PreparedStatement.setLong"


def test_collect_ops_orderlist_requires_allowlist(jdbc):
    m = match_binder(jdbc, _orderlist_ident())
    with pytest.raises(_RuntimeAbstain):
        collect_ops(m, jdbc, host_exprs={"h0": "col"}, allowlists={}, param_index=1)


def test_collect_ops_orderlist_with_allowlist_emits_guard(jdbc):
    m = match_binder(jdbc, _orderlist_ident())
    ops, _ = collect_ops(
        m, jdbc, host_exprs={"h0": "col"},
        allowlists={"h0": "ALLOWED_COLS"}, param_index=1,
    )
    assert len(ops) == 1
    assert isinstance(ops[0], AllowlistGuardOp)
    assert ops[0].allowlist_source == "ALLOWED_COLS"


def test_collect_ops_in_list_emits_inlist_op(jdbc):
    m = match_binder(jdbc, _in_expr())
    assert m is not None and m.binder.id == "sql-in-list"
    ops, next_idx = collect_ops(
        m, jdbc, host_exprs={"h0": "ids"}, allowlists={}, param_index=3,
    )
    # IN-list does NOT pre-advance param_index; stage F does that.
    assert next_idx == 3
    assert len(ops) == 1
    assert isinstance(ops[0], InListExpandOp)
    assert ops[0].hole_name == "h0"
    assert ops[0].api in (
        "java.sql.PreparedStatement.setLong",
        "java.sql.PreparedStatement.setInt",
        "java.sql.PreparedStatement.setObject",
    )


# --- API resolution ----------------------------------------------------------


def test_resolve_api_static_passthrough(jdbc):
    api = "java.sql.PreparedStatement.setString"
    h = Hole(name="h", ctx=SyntCtx.VALUE, sem=SemType.STRING)
    assert resolve_api(api, jdbc, h) == api


def test_resolve_api_choose_setter_macro_jdbc(jdbc):
    h = Hole(name="h", ctx=SyntCtx.VALUE, sem=SemType.STRING)
    api = resolve_api("{{ choose_setter($v.sem) }}", jdbc, h)
    assert api == "java.sql.PreparedStatement.setString"


def test_resolve_api_unknown_macro_returns_none(jdbc):
    h = Hole(name="h", ctx=SyntCtx.VALUE, sem=SemType.STRING)
    assert resolve_api("{{ unknown_macro($v) }}", jdbc, h) is None


def test_short_method_for_jdbc_api():
    assert short_method_for_api("java.sql.PreparedStatement.setString") == "setString"
    assert short_method_for_api("java.sql.PreparedStatement.setLong") == "setLong"


def test_short_method_for_unknown_api_uses_last_segment():
    assert short_method_for_api("subprocess.run") == "run"


# --- LDAP / XPath / Python DB-API catalogs ----------------------------------


def test_ldap_catalog_resolves_escape_helper():
    cat = load_catalog(BINDERS_DIR / "ldap.yaml")
    h = Hole(name="v", ctx=SyntCtx.VALUE, sem=SemType.STRING)
    api = resolve_api("{{ choose_ldap_escape($v) }}", cat, h)
    assert api in cat.parameterizing_apis


def test_xpath_catalog_resolves_variable_binding():
    cat = load_catalog(BINDERS_DIR / "xpath.yaml")
    h = Hole(name="v", ctx=SyntCtx.VALUE, sem=SemType.STRING)
    api = resolve_api("{{ choose_xpath_variable_binding($v) }}", cat, h)
    assert api in cat.parameterizing_apis


def test_pydbapi_catalog_resolves_setter_to_execute():
    cat = load_catalog(BINDERS_DIR / "sql_pydbapi.yaml")
    h = Hole(name="v", ctx=SyntCtx.VALUE, sem=SemType.STRING)
    api = resolve_api("{{ choose_setter($v.sem) }}", cat, h)
    assert api is not None
    assert api.endswith(".execute") or api.endswith(".executemany")
