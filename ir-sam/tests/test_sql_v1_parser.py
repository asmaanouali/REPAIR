"""Tests for the sqlglot-backed Stage D parser (sql_v1).

The v1 parser is opt-in via ``parser="v1"`` (or ``IRSAM_SQL_PARSER=v1``).
SQL₀ remains the default; these tests exercise the additional syntax
(JOINs, GROUP BY, HAVING, CTE, subqueries) and verify that hole markers
are recovered in the right syntactic context.
"""

from __future__ import annotations

import pytest

from core.iam import Hole, SemType, SIGNode, SyntCtx
from core.parsers import (
    SIGLift,
    SQL0AmbiguousIntent,
    SQL0SyntaxError,
    parse_template_to_sig,
)
from core.recon import ParameterizedTemplate, TemplateHole


def _tpl(text: str, *sems: str) -> ParameterizedTemplate:
    holes = tuple(
        TemplateHole(idx=i, host_expr=f"a{i}", sem=sem)
        for i, sem in enumerate(sems)
    )
    return ParameterizedTemplate(text=text, holes=holes)


def _holes(node):
    if isinstance(node, Hole):
        return [node]
    out = []
    if isinstance(node, SIGNode):
        for ch in node.children:
            out.extend(_holes(ch))
    return out


def test_v1_simple_select_value_hole():
    tpl = _tpl("SELECT id FROM users WHERE name = <<H0>>", "string")
    res = parse_template_to_sig(tpl, parser="v1")
    assert isinstance(res, SIGLift)
    assert len(res.holes) == 1
    assert res.holes[0].ctx == SyntCtx.VALUE
    assert res.holes[0].sem == SemType.STRING


def test_v1_join_with_value_hole():
    tpl = _tpl(
        "SELECT u.id FROM users u JOIN orders o ON u.id = o.uid "
        "WHERE u.name = <<H0>>",
        "string",
    )
    res = parse_template_to_sig(tpl, parser="v1")
    # Top-level Select must have a Join child.
    kinds = [c.kind for c in res.sig.children if isinstance(c, SIGNode)]
    assert "Join" in kinds
    assert len(res.holes) == 1
    assert res.holes[0].ctx == SyntCtx.VALUE


def test_v1_group_by_static_no_hole():
    tpl = _tpl(
        "SELECT u.id, COUNT(*) FROM users u "
        "WHERE u.active = <<H0>> GROUP BY u.id",
        "integer",
    )
    res = parse_template_to_sig(tpl, parser="v1")
    kinds = [c.kind for c in res.sig.children if isinstance(c, SIGNode)]
    assert "GroupBy" in kinds
    assert len(res.holes) == 1


def test_v1_having_value_hole():
    tpl = _tpl(
        "SELECT u.id FROM users u GROUP BY u.id HAVING COUNT(*) > <<H0>>",
        "integer",
    )
    res = parse_template_to_sig(tpl, parser="v1")
    kinds = [c.kind for c in res.sig.children if isinstance(c, SIGNode)]
    assert "Having" in kinds
    h = res.holes[0]
    assert h.ctx == SyntCtx.VALUE


def test_v1_cte_passthrough():
    tpl = _tpl(
        "WITH active AS (SELECT id FROM users WHERE flag = <<H0>>) "
        "SELECT id FROM active",
        "string",
    )
    res = parse_template_to_sig(tpl, parser="v1")
    assert res.sig.kind == "WithQuery"
    assert len(res.holes) == 1


def test_v1_subquery_in_from():
    tpl = _tpl(
        "SELECT s.id FROM (SELECT id FROM users WHERE name = <<H0>>) s",
        "string",
    )
    res = parse_template_to_sig(tpl, parser="v1")
    # Subquery node should appear underneath Select.
    found = False
    for c in res.sig.children:
        if isinstance(c, SIGNode) and c.kind == "Subquery":
            found = True
    assert found
    assert len(res.holes) == 1


def test_v1_table_position_hole_abstains():
    tpl = _tpl("SELECT id FROM <<H0>>", "string")
    with pytest.raises(SQL0AmbiguousIntent):
        parse_template_to_sig(tpl, parser="v1")


def test_v1_order_by_identifier_hole_is_ident_ctx():
    tpl = _tpl("SELECT id FROM users ORDER BY <<H0>>", "string")
    res = parse_template_to_sig(tpl, parser="v1")
    assert len(res.holes) == 1
    assert res.holes[0].ctx == SyntCtx.IDENTIFIER


def test_v1_limit_hole_force_integer():
    tpl = _tpl("SELECT id FROM users LIMIT <<H0>>", "string")
    res = parse_template_to_sig(tpl, parser="v1")
    h = res.holes[0]
    assert h.ctx == SyntCtx.VALUE
    assert h.sem == SemType.INTEGER


def test_v1_update_with_where_hole():
    tpl = _tpl(
        "UPDATE users SET name = <<H0>> WHERE id = <<H1>>",
        "string", "integer",
    )
    res = parse_template_to_sig(tpl, parser="v1")
    assert res.sig.kind == "Update"
    assert len(res.holes) == 2


def test_v1_delete_with_where_hole():
    tpl = _tpl("DELETE FROM users WHERE id = <<H0>>", "integer")
    res = parse_template_to_sig(tpl, parser="v1")
    assert res.sig.kind == "Delete"
    assert len(res.holes) == 1


def test_v1_insert_with_value_hole():
    tpl = _tpl(
        "INSERT INTO users (name, age) VALUES (<<H0>>, <<H1>>)",
        "string", "integer",
    )
    res = parse_template_to_sig(tpl, parser="v1")
    assert res.sig.kind == "Insert"
    assert len(res.holes) == 2


def test_v1_dialect_mysql_backticks_ok():
    tpl = _tpl(
        "SELECT `id` FROM `users` WHERE `name` = <<H0>>",
        "string",
    )
    res = parse_template_to_sig(tpl, parser="v1", dialect="mysql")
    assert len(res.holes) == 1


def test_v1_env_dispatch(monkeypatch):
    monkeypatch.setenv("IRSAM_SQL_PARSER", "v1")
    tpl = _tpl(
        "SELECT u.id FROM users u JOIN orders o ON u.id = o.uid "
        "WHERE u.name = <<H0>>",
        "string",
    )
    res = parse_template_to_sig(tpl)
    kinds = [c.kind for c in res.sig.children if isinstance(c, SIGNode)]
    assert "Join" in kinds


def test_v1_unsupported_dialect_raises():
    tpl = _tpl("SELECT 1", )
    with pytest.raises(SQL0SyntaxError):
        parse_template_to_sig(tpl, parser="v1", dialect="cobol-sql")


def test_default_parser_is_v1():
    """Sanity: with no env / kwarg the v1 (sqlglot) parser is selected and
    accepts JOIN syntax that the legacy SQL₀ parser rejected."""
    tpl = _tpl(
        "SELECT u.id FROM users u JOIN orders o ON u.id = o.uid "
        "WHERE u.name = <<H0>>",
        "string",
    )
    res = parse_template_to_sig(tpl)
    kinds = [c.kind for c in res.sig.children if isinstance(c, SIGNode)]
    assert "Join" in kinds


def test_sql0_optin_rejects_join(monkeypatch):
    """The legacy SQL₀ parser is still reachable via parser="sql0" and rejects
    JOIN syntax."""
    monkeypatch.delenv("IRSAM_SQL_PARSER", raising=False)
    tpl = _tpl(
        "SELECT u.id FROM users u JOIN orders o ON u.id = o.uid "
        "WHERE u.name = <<H0>>",
        "string",
    )
    with pytest.raises((SQL0SyntaxError, SQL0AmbiguousIntent)):
        parse_template_to_sig(tpl, parser="sql0")


def test_v1_in_list_disambig_hint_csv():
    tpl = _tpl("SELECT id FROM users WHERE id IN (<<H0>>)", "string")
    res = parse_template_to_sig(
        tpl, parser="v1",
        disambig_hints={"h0": "in_list_csv"},
    )
    h = res.holes[0]
    # IN-list hole gets promoted to MANY_BOUNDED.
    assert h.card.name == "MANY_BOUNDED"
