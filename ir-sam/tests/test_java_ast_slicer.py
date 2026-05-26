"""Phase 2 — tree-sitter Java AST slicer tests.

Exercise tricky shapes the AST tier handles that the regex slicer
either abstains on or mis-handles, and verify equivalence on the
standard shapes by running the same fixtures through both engines.
"""

from __future__ import annotations

import os

import pytest

from core.slicer import (
    SliceAbstention,
    SliceResult,
    _slice_sink_argument_regex,
    find_sink_calls,
    slice_sink_argument,
)


@pytest.fixture
def ts_env(monkeypatch):
    monkeypatch.setenv("IRSAM_SLICER", "ts")
    yield


SRC_BASIC = """\
package x;
import java.sql.*;

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


def test_ts_concat_parity(ts_env):
    sinks = find_sink_calls(SRC_BASIC)
    line, *_ = sinks[0]
    res = slice_sink_argument(SRC_BASIC, line)
    assert isinstance(res, SliceResult)
    assert any(p.kind == "literal" and "SELECT id FROM users" in p.value
               for p in res.parts)
    assert any(p.kind == "var" and p.value == "userName" for p in res.parts)


def test_ts_and_regex_agree_on_concat():
    sinks = find_sink_calls(SRC_BASIC)
    line, *_ = sinks[0]
    regex_res = _slice_sink_argument_regex(SRC_BASIC, line)
    os.environ["IRSAM_SLICER"] = "ts"
    try:
        ts_res = slice_sink_argument(SRC_BASIC, line)
    finally:
        del os.environ["IRSAM_SLICER"]
    assert isinstance(regex_res, SliceResult)
    assert isinstance(ts_res, SliceResult)
    assert regex_res.parts == ts_res.parts
    assert regex_res.sink_var_name == ts_res.sink_var_name


SRC_PARENS = """\
public class P {
    public void bad(String name, java.sql.Statement stmt) throws Exception {
        String sql = ("SELECT * FROM t WHERE n = '") + (name) + ("'");
        stmt.executeQuery(sql);
    }
}
"""


def test_ts_handles_parenthesized_concat(ts_env):
    sinks = find_sink_calls(SRC_PARENS)
    line, *_ = sinks[0]
    res = slice_sink_argument(SRC_PARENS, line)
    assert isinstance(res, SliceResult)
    assert any(p.kind == "literal" and "SELECT * FROM t" in p.value
               for p in res.parts)
    assert any(p.kind == "var" and p.value == "name" for p in res.parts)


SRC_REASSIGN = """\
public class R {
    public void bad(String tail, java.sql.Statement stmt) throws Exception {
        String sql = "SELECT * FROM users";
        sql = sql + " WHERE id = '" + tail + "'";
        stmt.executeQuery(sql);
    }
}
"""


def test_ts_handles_self_reassignment(ts_env):
    sinks = find_sink_calls(SRC_REASSIGN)
    line, *_ = sinks[0]
    res = slice_sink_argument(SRC_REASSIGN, line)
    assert isinstance(res, SliceResult)
    # The post-assignment value should drive the slice (latest binding wins).
    literals = " ".join(p.value for p in res.parts if p.kind == "literal")
    assert "SELECT * FROM users" in literals
    assert " WHERE id = '" in literals
    assert any(p.kind == "var" and p.value == "tail" for p in res.parts)


SRC_PLUSEQ = """\
public class PE {
    public void bad(String tail, java.sql.Statement stmt) throws Exception {
        String sql = "SELECT * FROM t";
        sql += " WHERE n = '";
        sql += tail;
        sql += "'";
        stmt.executeQuery(sql);
    }
}
"""


def test_ts_handles_plus_eq_appends(ts_env):
    sinks = find_sink_calls(SRC_PLUSEQ)
    line, *_ = sinks[0]
    res = slice_sink_argument(SRC_PLUSEQ, line)
    assert isinstance(res, SliceResult)
    literals = " ".join(p.value for p in res.parts if p.kind == "literal")
    assert "SELECT * FROM t" in literals
    assert "WHERE n =" in literals


SRC_TERNARY = """\
public class T {
    public void bad(boolean flag, String n, java.sql.Statement stmt) throws Exception {
        String sql = flag ? "SELECT a FROM t" : "SELECT b FROM t";
        stmt.executeQuery(sql);
    }
}
"""


def test_ts_ternary_is_opaque(ts_env):
    sinks = find_sink_calls(SRC_TERNARY)
    line, *_ = sinks[0]
    res = slice_sink_argument(SRC_TERNARY, line)
    # No literal skeleton recoverable → conservative abstention.
    assert isinstance(res, SliceAbstention)
    assert res.reason == "no_static_sql_skeleton"


SRC_FIND_TWO = """\
public class F {
    public void bad(java.sql.Connection c, String a, String b) throws Exception {
        c.prepareStatement("X").executeQuery();
        java.sql.Statement s = c.createStatement();
        s.executeUpdate("UPDATE t SET x = '" + a + "'");
    }
}
"""


def test_ts_find_sink_calls_finds_all(ts_env):
    sinks = find_sink_calls(SRC_FIND_TWO)
    apis = sorted(s[2] for s in sinks)
    # Tree-sitter sees executeQuery, executeUpdate, createStatement, prepareStatement.
    assert "executeUpdate" in apis
    assert "prepareStatement" in apis


SRC_NO_METHOD = "class X {}"


def test_ts_no_method_abstains(ts_env):
    res = slice_sink_argument(SRC_NO_METHOD, 1)
    assert isinstance(res, SliceAbstention)
    assert res.reason in ("sink_not_found", "no_enclosing_method")


SRC_STRING_FORMAT = """\
public class SF {
    public void bad(String name, java.sql.Statement stmt) throws Exception {
        String sql = String.format("SELECT * FROM t WHERE n='%s'", name);
        stmt.executeQuery(sql);
    }
}
"""


def test_ts_string_format_extracts_skeleton(ts_env):
    sinks = find_sink_calls(SRC_STRING_FORMAT)
    line, *_ = sinks[0]
    res = slice_sink_argument(SRC_STRING_FORMAT, line)
    assert isinstance(res, SliceResult)
    literals = " ".join(p.value for p in res.parts if p.kind == "literal")
    assert "SELECT * FROM t WHERE n='%s'" in literals
    assert any(p.kind == "var" and p.value == "name" for p in res.parts)
