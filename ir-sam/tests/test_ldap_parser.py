"""Tests for the LDAP filter parser (Phase 4, stage D)."""
from core.parsers.ldap import (
    LDAPAmbiguousIntent, LDAPSyntaxError, parse_template_to_sig,
)
from core.recon import ParameterizedTemplate, TemplateHole
from core.iam import Hole, SyntCtx


def _tpl(text, holes):
    return ParameterizedTemplate(text=text, holes=tuple(holes))


def test_ldap_equality_value_hole():
    h = TemplateHole(idx=0, host_expr="uid", sem="string", in_string_literal=False)
    lift = parse_template_to_sig(_tpl("(uid=<<H0>>)", [h]))
    assert lift.sig.kind == "LdapEquality"
    assert len(lift.holes) == 1
    assert lift.holes[0].ctx is SyntCtx.VALUE


def test_ldap_substring_value_hole():
    h = TemplateHole(idx=0, host_expr="pat", sem="string", in_string_literal=False)
    lift = parse_template_to_sig(_tpl("(cn=*<<H0>>*)", [h]))
    assert lift.sig.kind == "LdapSubstring"
    assert len(lift.holes) == 1


def test_ldap_and_of_two_equalities():
    h0 = TemplateHole(idx=0, host_expr="u", sem="string", in_string_literal=False)
    h1 = TemplateHole(idx=1, host_expr="p", sem="string", in_string_literal=False)
    lift = parse_template_to_sig(_tpl("(&(uid=<<H0>>)(mail=<<H1>>))", [h0, h1]))
    assert lift.sig.kind == "LdapAnd"
    assert len(lift.holes) == 2


def test_ldap_present_filter():
    lift = parse_template_to_sig(_tpl("(uid=*)", []))
    assert lift.sig.kind == "LdapPresent"
    assert len(lift.holes) == 0


def test_ldap_bad_filter_raises():
    try:
        parse_template_to_sig(_tpl("uid=foo", []))
    except LDAPSyntaxError:
        return
    raise AssertionError("expected LDAPSyntaxError")
