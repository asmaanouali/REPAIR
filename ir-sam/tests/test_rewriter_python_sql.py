"""Unit tests for the Python DB-API SQL rewriter (Phase 5).

Covers the two formerly-abstained paths:

* IN-list expansion (``param_index == -1``): dynamic ``", ".join("?")``
  placeholders + ``*tuple`` argument unpacking.
* Identifier allow-list guards: runtime ``in <frozenset>`` assertion
  + string substitution of the literal identifier into the template.
"""

from __future__ import annotations

import textwrap

import pytest

from core.phi import AllowlistGuard, PatchPlan, SetterCall
from core.rewriter import RewriteAbstention
from core.rewriter.python_sql import synthesize_python_sql_patch
from core.slicer import SliceResult


def _slice(src: str, sink_call: str) -> SliceResult:
    """Locate ``sink_call`` in ``src`` and build a minimal SliceResult."""
    for i, line in enumerate(src.splitlines(), start=1):
        if sink_call in line:
            return SliceResult(
                parts=(),
                method_text=src,
                method_start_line=1,
                sink_call_text=sink_call,
                sink_call_line=i,
                sink_var_name=None,
                declarations_to_remove=(),
            )
    raise AssertionError(f"sink call not found: {sink_call!r}")


# --- IN-list expansion --------------------------------------------------------


def test_python_sql_in_list_expansion_emits_dynamic_placeholders():
    src = textwrap.dedent(
        '''\
        import sqlite3

        def get_users(conn, ids):
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE id IN (" + ",".join(map(str, ids)) + ")")
            return cur.fetchall()
        '''
    )
    sink = (
        'cur.execute("SELECT * FROM users WHERE id IN (" + '
        '",".join(map(str, ids)) + ")")'
    )
    sl = _slice(src, sink)

    plan = PatchPlan(
        prepared_template="SELECT * FROM users WHERE id IN (__INLIST_ids__)",
        setter_calls=(
            SetterCall(
                param_index=-1,
                api="sqlite3.Cursor.execute",
                short_method="execute",
                host_expr="ids",
                hole_name="ids",
            ),
        ),
        allowlist_guards=(),
        realizations=(),
        catalog_id="sql_pydbapi",
        binder_ids_used=("sql-in-list",),
        proof_obligations=("Lemma 1 (Parameter inertness), list induction.",),
    )

    out = synthesize_python_sql_patch(src, sl, plan)
    p = out.patched_source

    # The original concatenation must be gone.
    assert '",".join(map(str, ids))' not in p
    # A runtime placeholder expansion must be present.
    assert '", ".join(["?"] * len(__irsam_list_ids))' in p
    # The host list must be tupled and unpacked into the args tuple.
    assert "__irsam_list_ids = tuple(ids)" in p
    assert "*__irsam_list_ids" in p
    # The marker token must no longer appear in the generated SQL.
    assert "__INLIST_ids__" in p  # only as a string-literal replace key
    # The marker token must NOT survive as an unsubstituted SQL fragment.
    # Confirm via .replace call presence:
    assert ".replace(\"__INLIST_ids__\"" in p


def test_python_sql_in_list_token_missing_abstains():
    src = "cur.execute('SELECT 1')\n"
    sl = _slice(src, "cur.execute('SELECT 1')")
    plan = PatchPlan(
        # IN-list setter declared but template has no marker -> abstain.
        prepared_template="SELECT 1",
        setter_calls=(
            SetterCall(
                param_index=-1, api="sqlite3.Cursor.execute",
                short_method="execute", host_expr="ids", hole_name="ids",
            ),
        ),
        allowlist_guards=(),
        realizations=(),
        catalog_id="sql_pydbapi",
        binder_ids_used=(),
        proof_obligations=(),
    )
    with pytest.raises(RewriteAbstention, match="IN-list token"):
        synthesize_python_sql_patch(src, sl, plan)


# --- Allow-list identifier guards --------------------------------------------


def test_python_sql_allowlist_guard_emits_assertion_and_substitution():
    src = textwrap.dedent(
        '''\
        import sqlite3

        def query(conn, table, name):
            cur = conn.cursor()
            cur.execute("SELECT * FROM " + table + " WHERE name = '" + name + "'")
            return cur.fetchall()
        '''
    )
    sink = (
        'cur.execute("SELECT * FROM " + table + " WHERE name = \'" + name + "\'")'
    )
    sl = _slice(src, sink)

    plan = PatchPlan(
        prepared_template="SELECT * FROM {__GUARD_table__} WHERE name = ?",
        setter_calls=(
            SetterCall(
                param_index=1, api="sqlite3.Cursor.execute",
                short_method="execute", host_expr="name", hole_name="name",
            ),
        ),
        allowlist_guards=(
            AllowlistGuard(
                hole_name="table",
                host_expr="table",
                allowlist_java_const="IrsamAllowlists.TABLES",
            ),
        ),
        realizations=(),
        catalog_id="sql_pydbapi",
        binder_ids_used=("sql-from-ident", "sql-eq-value"),
        proof_obligations=(
            "Lemma 1 (Parameter inertness).",
            "Lemma 2 (Identifier allow-list closure).",
        ),
    )

    out = synthesize_python_sql_patch(src, sl, plan)
    p = out.patched_source

    # Allow-list assertion must be present.
    assert "if table not in _ALLOWLIST_TABLES:" in p
    assert "raise ValueError" in p
    # The bound identifier variable must be set.
    assert "__irsam_g_table = table" in p
    # The template-substitution helper must replace the guard marker.
    assert ".replace(\"{__GUARD_table__}\", __irsam_g_table)" in p
    # The scalar host expression must reach the args tuple.
    assert "__irsam_sql, (name,)" in p
    # The original concatenation must be gone.
    assert '" + table + "' not in p


def test_python_sql_allowlist_guard_missing_host_expr_abstains():
    src = "cur.execute('SELECT 1')\n"
    sl = _slice(src, "cur.execute('SELECT 1')")
    plan = PatchPlan(
        prepared_template="SELECT * FROM {__GUARD_table__}",
        setter_calls=(),
        allowlist_guards=(
            AllowlistGuard(
                hole_name="table",
                host_expr="",  # empty -> abstain
                allowlist_java_const="IrsamAllowlists.TABLES",
            ),
        ),
        realizations=(),
        catalog_id="sql_pydbapi",
        binder_ids_used=(),
        proof_obligations=(),
    )
    with pytest.raises(RewriteAbstention, match="no host expression"):
        synthesize_python_sql_patch(src, sl, plan)


# --- Combined identifier + IN-list (smoke) -----------------------------------


def test_python_sql_combined_identifier_and_inlist():
    src = (
        'cur.execute("SELECT * FROM " + tbl + " WHERE id IN (" + '
        '",".join(map(str, ids)) + ")")\n'
    )
    sink = src.rstrip("\n")
    sl = _slice(src, sink)

    plan = PatchPlan(
        prepared_template=(
            "SELECT * FROM {__GUARD_tbl__} WHERE id IN (__INLIST_ids__)"
        ),
        setter_calls=(
            SetterCall(
                param_index=-1, api="sqlite3.Cursor.execute",
                short_method="execute", host_expr="ids", hole_name="ids",
            ),
        ),
        allowlist_guards=(
            AllowlistGuard(
                hole_name="tbl",
                host_expr="tbl",
                allowlist_java_const="IrsamAllowlists.TABLES",
            ),
        ),
        realizations=(),
        catalog_id="sql_pydbapi",
        binder_ids_used=(),
        proof_obligations=(),
    )
    out = synthesize_python_sql_patch(src, sl, plan)
    p = out.patched_source

    assert "if tbl not in _ALLOWLIST_TABLES:" in p
    assert "__irsam_list_ids = tuple(ids)" in p
    assert "*__irsam_list_ids" in p
    # No scalar args -> args tuple is only the unpack.
    assert "(*__irsam_list_ids)" in p or "(*__irsam_list_ids," in p
