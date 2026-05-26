"""Tests for the Phase-4 Python slicer (PEP-249 cursor.execute)."""
from core.lang.python import (
    find_sink_calls, slice_sink_argument,
)
from core.slicer import SliceAbstention, SliceResult


_SRC_CONCAT = """
import sqlite3
def fetch_user(conn, name: str):
    cur = conn.cursor()
    sql = "SELECT id FROM users WHERE name = '" + name + "'"
    cur.execute(sql)
    return cur.fetchall()
"""

_SRC_FSTRING = """
import sqlite3
def find_id(conn, name: str):
    cur = conn.cursor()
    cur.execute(f"SELECT id FROM users WHERE name = '{name}'")
    return cur.fetchone()
"""

_SRC_PCT = """
import sqlite3
def get_by_id(conn, uid: int):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = %d" % uid)
"""


def _sink_line(src):
    return find_sink_calls(src)[0][0]


def test_find_sink_calls_finds_execute():
    sinks = find_sink_calls(_SRC_CONCAT)
    assert len(sinks) == 1
    assert sinks[0][2] == "execute"


def test_slice_python_concat():
    res = slice_sink_argument(_SRC_CONCAT, _sink_line(_SRC_CONCAT))
    assert isinstance(res, SliceResult)
    assert any(p.kind == "literal" for p in res.parts)
    var_parts = [p for p in res.parts if p.kind == "var"]
    assert var_parts and var_parts[0].value == "name"


def test_slice_python_fstring():
    res = slice_sink_argument(_SRC_FSTRING, _sink_line(_SRC_FSTRING))
    assert isinstance(res, SliceResult)
    var_parts = [p for p in res.parts if p.kind == "var"]
    assert var_parts and var_parts[0].value == "name"


def test_slice_python_percent_format_int_param():
    res = slice_sink_argument(_SRC_PCT, _sink_line(_SRC_PCT))
    assert isinstance(res, SliceResult)
    var = [p for p in res.parts if p.kind == "var"][0]
    # uid annotated int -> sem integer (via java mapping)
    assert var.java_type in ("int", "long", "Integer", "Long")


# ---------------------------------------------------------------------------
# Phase 3: libcst slicer (opt-in via IRSAM_PY_SLICER=cst).
# ---------------------------------------------------------------------------

import pytest


@pytest.fixture
def cst_env(monkeypatch):
    monkeypatch.setenv("IRSAM_PY_SLICER", "cst")


_SRC_AUGASSIGN = """
import sqlite3
def find(conn, name: str):
    cur = conn.cursor()
    sql = "SELECT id FROM users WHERE 1=1"
    sql += " AND name = '" + name + "'"
    cur.execute(sql)
"""

_SRC_DOT_FORMAT = """
import sqlite3
def find(conn, name: str):
    cur = conn.cursor()
    cur.execute("SELECT * FROM t WHERE n = '{n}'".format(n=name))
"""

_SRC_DOT_FORMAT_POSITIONAL = """
import sqlite3
def find(conn, name: str):
    cur = conn.cursor()
    cur.execute("SELECT * FROM t WHERE n = '{}'".format(name))
"""

_SRC_PCT_TUPLE = """
import sqlite3
def find(conn, uid: int, name: str):
    cur = conn.cursor()
    cur.execute("SELECT * FROM u WHERE id=%d AND name='%s'" % (uid, name))
"""

_SRC_DOTTED_RECV = """
class R:
    def find(self, name: str):
        self.cur.execute("SELECT * FROM t WHERE n='" + name + "'")
"""

_SRC_PARSE_ERROR = """
def f(:
    pass
"""


def test_cst_concat(cst_env):
    res = slice_sink_argument(_SRC_CONCAT, _sink_line(_SRC_CONCAT))
    assert isinstance(res, SliceResult)
    assert any(p.kind == "var" and p.value == "name" for p in res.parts)


def test_cst_fstring(cst_env):
    res = slice_sink_argument(_SRC_FSTRING, _sink_line(_SRC_FSTRING))
    assert isinstance(res, SliceResult)
    assert any(p.kind == "var" and p.value == "name" for p in res.parts)


def test_cst_percent_int(cst_env):
    res = slice_sink_argument(_SRC_PCT, _sink_line(_SRC_PCT))
    assert isinstance(res, SliceResult)
    var = [p for p in res.parts if p.kind == "var"][0]
    assert var.value == "uid"
    assert var.java_type in ("int", "long")


def test_cst_aug_assign(cst_env):
    res = slice_sink_argument(_SRC_AUGASSIGN, _sink_line(_SRC_AUGASSIGN))
    assert isinstance(res, SliceResult)
    # Both the original SELECT and the appended AND clause must survive.
    lits = " ".join(p.value for p in res.parts if p.kind == "literal")
    assert "SELECT id FROM users" in lits
    assert "AND name" in lits
    assert any(p.kind == "var" and p.value == "name" for p in res.parts)


def test_cst_dot_format_kw(cst_env):
    res = slice_sink_argument(_SRC_DOT_FORMAT, _sink_line(_SRC_DOT_FORMAT))
    assert isinstance(res, SliceResult)
    assert any(p.kind == "var" and p.value == "name" for p in res.parts)


def test_cst_dot_format_positional(cst_env):
    res = slice_sink_argument(_SRC_DOT_FORMAT_POSITIONAL,
                              _sink_line(_SRC_DOT_FORMAT_POSITIONAL))
    assert isinstance(res, SliceResult)
    assert any(p.kind == "var" and p.value == "name" for p in res.parts)


def test_cst_percent_tuple_multi(cst_env):
    res = slice_sink_argument(_SRC_PCT_TUPLE, _sink_line(_SRC_PCT_TUPLE))
    assert isinstance(res, SliceResult)
    vars_ = [p for p in res.parts if p.kind == "var"]
    assert any(v.value == "uid" for v in vars_)
    assert any(v.value == "name" for v in vars_)


def test_cst_dotted_receiver_finds_sink(cst_env):
    sinks = find_sink_calls(_SRC_DOTTED_RECV)
    assert len(sinks) == 1
    assert sinks[0][2] == "execute"
    res = slice_sink_argument(_SRC_DOTTED_RECV, sinks[0][0])
    assert isinstance(res, SliceResult)
    assert any(p.kind == "var" and p.value == "name" for p in res.parts)


def test_cst_parse_error_returns_abstention(cst_env):
    res = slice_sink_argument(_SRC_PARSE_ERROR, 2)
    # parse error should yield an abstention or fall back gracefully
    assert isinstance(res, (SliceAbstention, SliceResult))
    if isinstance(res, SliceAbstention):
        assert res.reason in ("parse_error", "sink_not_found",
                              "no_enclosing_method", "no_sink_argument",
                              "no_static_sql_skeleton")
