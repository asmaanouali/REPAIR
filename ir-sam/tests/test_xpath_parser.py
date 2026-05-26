"""Tests for the XPath subset parser (Phase 4, stage D)."""
from core.parsers.xpath import (
    XPathAmbiguousIntent, XPathSyntaxError, parse_template_to_sig,
)
from core.recon import ParameterizedTemplate, TemplateHole
from core.iam import SyntCtx


def _tpl(text, holes):
    return ParameterizedTemplate(text=text, holes=tuple(holes))


def test_xpath_predicate_eq_with_hole():
    h = TemplateHole(idx=0, host_expr="name", sem="string", in_string_literal=False)
    lift = parse_template_to_sig(_tpl("user[@name=<<H0>>]", [h]))
    assert lift.sig.kind == "XPathPath"
    # one value hole
    assert len(lift.holes) == 1
    assert lift.holes[0].ctx is SyntCtx.VALUE


def test_xpath_contains_function():
    h = TemplateHole(idx=0, host_expr="q", sem="string", in_string_literal=False)
    lift = parse_template_to_sig(_tpl("user[contains(@name,<<H0>>)]", [h]))
    assert len(lift.holes) == 1


def test_xpath_starts_with_function():
    h = TemplateHole(idx=0, host_expr="q", sem="string", in_string_literal=False)
    lift = parse_template_to_sig(_tpl("user[starts-with(@name,<<H0>>)]", [h]))
    assert len(lift.holes) == 1


def test_xpath_attr_hole_abstains():
    h = TemplateHole(idx=0, host_expr="attr", sem="string", in_string_literal=False)
    try:
        parse_template_to_sig(_tpl("user[@<<H0>>='x']", [h]))
    except (XPathAmbiguousIntent, XPathSyntaxError):
        return
    raise AssertionError("expected ambiguous/abstention on attribute-name hole")
