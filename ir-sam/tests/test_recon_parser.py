"""Stage C+D unit tests."""

from __future__ import annotations

import pytest

from core.iam import Hole, SemType, SyntCtx
from core.parsers import (
    SQL0AmbiguousIntent,
    parse_template_to_sig,
)
from core.recon import ParameterizedTemplate, TemplateHole, reconstruct
from core.slicer import SliceResult, StringPart


def _slice(parts):
    return SliceResult(
        parts=tuple(parts),
        method_text="",
        method_start_line=1,
        sink_call_text="stmt.executeQuery(sql)",
        sink_call_line=1,
        sink_var_name="sql",
    )


def test_reconstruct_eq_int_template():
    parts = [
        StringPart.lit("SELECT * FROM t WHERE id = "),
        StringPart.var("id", "int"),
    ]
    tpl = reconstruct(_slice(parts))
    assert isinstance(tpl, ParameterizedTemplate)
    assert tpl.text == "SELECT * FROM t WHERE id = <<H0>>"
    assert tpl.holes == (TemplateHole(idx=0, host_expr="id", sem="integer",
                                       in_string_literal=False),)


def test_parse_select_eq_int():
    tpl = ParameterizedTemplate(
        text="SELECT id FROM users WHERE id = <<H0>>",
        holes=(TemplateHole(idx=0, host_expr="id", sem="integer"),),
    )
    lift = parse_template_to_sig(tpl)
    assert lift.sig.kind == "Select"
    assert lift.holes == (Hole(name="h0", ctx=SyntCtx.VALUE,
                                sem=SemType.INTEGER),)


def test_parse_select_like():
    tpl = ParameterizedTemplate(
        text="SELECT id FROM users WHERE username LIKE <<H0>>",
        holes=(TemplateHole(idx=0, host_expr="q", sem="string"),),
    )
    lift = parse_template_to_sig(tpl)
    assert lift.sig.kind == "Select"
    assert lift.holes[0].sem is SemType.STRING


def test_parse_table_name_hole_abstains():
    tpl = ParameterizedTemplate(
        text="SELECT * FROM <<H0>>",
        holes=(TemplateHole(idx=0, host_expr="t", sem="string"),),
    )
    with pytest.raises(SQL0AmbiguousIntent):
        parse_template_to_sig(tpl)


def test_parse_orderby_ident_hole():
    tpl = ParameterizedTemplate(
        text="SELECT id FROM users ORDER BY <<H0>>",
        holes=(TemplateHole(idx=0, host_expr="col", sem="string"),),
    )
    lift = parse_template_to_sig(tpl)
    assert lift.holes[0].ctx is SyntCtx.IDENTIFIER


def test_parse_update_with_holes():
    tpl = ParameterizedTemplate(
        text="UPDATE users SET email = <<H0>> WHERE id = <<H1>>",
        holes=(
            TemplateHole(idx=0, host_expr="v", sem="string"),
            TemplateHole(idx=1, host_expr="id", sem="integer"),
        ),
    )
    lift = parse_template_to_sig(tpl)
    assert lift.sig.kind == "Update"
    assert [h.sem for h in lift.holes] == [SemType.STRING, SemType.INTEGER]


def test_parse_delete_with_hole():
    tpl = ParameterizedTemplate(
        text="DELETE FROM users WHERE id = <<H0>>",
        holes=(TemplateHole(idx=0, host_expr="id", sem="integer"),),
    )
    lift = parse_template_to_sig(tpl)
    assert lift.sig.kind == "Delete"


def test_parse_insert_with_holes():
    tpl = ParameterizedTemplate(
        text="INSERT INTO users(email) VALUES(<<H0>>)",
        holes=(TemplateHole(idx=0, host_expr="email", sem="string"),),
    )
    lift = parse_template_to_sig(tpl)
    assert lift.sig.kind == "Insert"


def test_parse_limit_hole():
    tpl = ParameterizedTemplate(
        text="SELECT * FROM users LIMIT <<H0>>",
        holes=(TemplateHole(idx=0, host_expr="n", sem="integer"),),
    )
    lift = parse_template_to_sig(tpl)
    assert lift.sig.kind == "Select"
    assert lift.holes[0].sem is SemType.INTEGER
