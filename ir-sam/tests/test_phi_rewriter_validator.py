"""Stage E + F + G unit tests and end-to-end pipeline tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.binder.loader import load_catalog
from core.iam import Hole, IAM, SemType, SyntCtx
from core.parsers import parse_template_to_sig
from core.phi import PatchPlan, PhiAbstention, apply_phi, build_iam_from_lift
from core.recon import ParameterizedTemplate, TemplateHole, reconstruct
from core.rewriter import synthesize_patch
from core.slicer import slice_sink_argument, find_sink_calls
from core.validator import (
    run_compile_gate,
    run_differential_gate,
    run_resast_gate,
    run_structural_gate,
)


CATALOG = Path(__file__).resolve().parents[1] / "binders" / "sql_jdbc.yaml"
catalog = load_catalog(CATALOG)


# ----- Stage E: \u03c6 ----------------------------------------------------------


def _lift(tpl_text: str, holes: tuple[TemplateHole, ...]):
    return parse_template_to_sig(ParameterizedTemplate(tpl_text, holes))


def test_phi_eq_string_produces_setString_plan():
    lift = _lift("SELECT id FROM users WHERE name = <<H0>>",
                 (TemplateHole(0, "userName", "string"),))
    plan = apply_phi(lift.sig, lift.holes, {"h0": "userName"}, catalog)
    assert isinstance(plan, PatchPlan)
    assert plan.prepared_template == "SELECT id FROM users WHERE name = ?"
    assert plan.setter_calls[0].short_method == "setString"
    assert plan.setter_calls[0].param_index == 1
    assert plan.realizations[0].api in catalog.parameterizing_apis


def test_phi_eq_int_produces_setLong_plan():
    lift = _lift("SELECT id FROM users WHERE id = <<H0>>",
                 (TemplateHole(0, "id", "integer"),))
    plan = apply_phi(lift.sig, lift.holes, {"h0": "id"}, catalog)
    assert isinstance(plan, PatchPlan)
    assert plan.setter_calls[0].short_method == "setLong"


def test_phi_orderby_without_allowlist_abstains():
    lift = _lift("SELECT id FROM users ORDER BY <<H0>>",
                 (TemplateHole(0, "col", "string"),))
    plan = apply_phi(lift.sig, lift.holes, {"h0": "col"}, catalog)
    assert isinstance(plan, PhiAbstention)
    assert plan.reason == "no_allowlist"


def test_phi_orderby_with_allowlist_succeeds():
    lift = _lift("SELECT id FROM users ORDER BY <<H0>>",
                 (TemplateHole(0, "col", "string"),))
    plan = apply_phi(lift.sig, lift.holes, {"h0": "col"}, catalog,
                     allowlists={"h0": "ALLOWED_COLS"})
    assert isinstance(plan, PatchPlan)
    assert plan.allowlist_guards[0].allowlist_java_const == "ALLOWED_COLS"
    assert plan.realizations[0].via == "allowlist-lookup"


# ----- Stage F: rewriter ------------------------------------------------------


_SRC = """\
package juliet.cwe89;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class A {
    public ResultSet bad(String userName) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement stmt = conn.createStatement();
        String sql = "SELECT id FROM users WHERE name = '" + userName + "'";
        ResultSet rs = stmt.executeQuery(sql);
        return rs;
    }
}
"""


def test_end_to_end_rewriter_eq_string():
    sinks = find_sink_calls(_SRC)
    sl = slice_sink_argument(_SRC, sinks[0][0])
    tpl = reconstruct(sl)
    lift = parse_template_to_sig(tpl)
    host_exprs = {f"h{th.idx}": th.host_expr for th in tpl.holes}
    plan = apply_phi(lift.sig, lift.holes, host_exprs, catalog)
    assert isinstance(plan, PatchPlan)
    patch = synthesize_patch(_SRC, sl, plan)
    assert "PreparedStatement" in patch.patched_source
    assert "setString(1, userName)" in patch.patched_source
    assert patch.connection_var == "conn"
    # The original concatenation must be gone:
    assert '"\' + userName + \'"' not in patch.patched_source
    assert "__irsam_ps.executeQuery()" in patch.patched_source


# ----- Stage G: gates ---------------------------------------------------------


def test_resast_gate_flags_concat():
    bad = """class X {
        void f(String n, java.sql.Statement s) throws Exception {
            s.executeQuery("SELECT * FROM t WHERE n='" + n + "'");
        }
    }"""
    out = run_resast_gate(bad)
    assert not out.passed


def test_resast_gate_accepts_prepared():
    good = """class X {
        void f(String n, java.sql.Connection c) throws Exception {
            java.sql.PreparedStatement ps = c.prepareStatement("SELECT * FROM t WHERE n=?");
            ps.setString(1, n);
            ps.executeQuery();
        }
    }"""
    out = run_resast_gate(good)
    assert out.passed, out.detail


def test_structural_gate_via_iam():
    lift = _lift("SELECT id FROM users WHERE id = <<H0>>",
                 (TemplateHole(0, "id", "integer"),))
    iam = build_iam_from_lift(lift, {"h0": "id"})
    plan = apply_phi(lift.sig, lift.holes, {"h0": "id"}, catalog)
    assert isinstance(plan, PatchPlan)
    out = run_structural_gate(iam, plan.realizations, set(catalog.parameterizing_apis))
    assert out.passed, out.detail


def test_differential_gate_string_param_safe():
    out = run_differential_gate(
        original_concat_template="SELECT * FROM users WHERE username = '{p}'",
        patched_prepared_template="SELECT * FROM users WHERE username = ?",
        param_kind="string",
    )
    assert out.passed, out.detail


def test_differential_gate_int_param_safe():
    out = run_differential_gate(
        original_concat_template="SELECT * FROM users WHERE id = {p}",
        patched_prepared_template="SELECT * FROM users WHERE id = ?",
        param_kind="integer",
    )
    assert out.passed, out.detail
