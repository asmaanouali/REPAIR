"""Stage B unit tests."""

from __future__ import annotations

from core.slicer import (
    SliceAbstention,
    SliceResult,
    find_sink_calls,
    slice_sink_argument,
)


SRC = """\
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


def test_find_sink_calls():
    sinks = find_sink_calls(SRC)
    assert len(sinks) == 1
    line, recv, api, _text = sinks[0]
    assert api == "executeQuery"
    assert recv == "stmt"


def test_slice_string_concat():
    sinks = find_sink_calls(SRC)
    line, *_ = sinks[0]
    res = slice_sink_argument(SRC, line)
    assert isinstance(res, SliceResult)
    parts = res.parts
    assert any(p.kind == "literal" and "SELECT id FROM users" in p.value for p in parts)
    assert any(p.kind == "var" and p.value == "userName" for p in parts)


SB_SRC = """\
package x;
import java.sql.*;

public class B {
    public ResultSet bad(String q) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement stmt = conn.createStatement();
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT id FROM users WHERE name = '");
        sb.append(q);
        sb.append("'");
        String sql = sb.toString();
        ResultSet rs = stmt.executeQuery(sql);
        return rs;
    }
}
"""


def test_slice_stringbuilder_chain():
    sinks = find_sink_calls(SB_SRC)
    line, *_ = sinks[0]
    res = slice_sink_argument(SB_SRC, line)
    assert isinstance(res, SliceResult)
    parts = res.parts
    assert any(p.kind == "literal" and "SELECT id FROM users" in p.value for p in parts)
    assert any(p.kind == "var" and p.value == "q" for p in parts)


def test_slice_abstain_when_no_method():
    res = slice_sink_argument("class X {}", 1)
    assert isinstance(res, SliceAbstention)
