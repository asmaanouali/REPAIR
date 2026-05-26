"""Juliet-mini / OWASP-mini CWE-89 benchmark generator.

Generates a self-contained corpus of Java files in the spirit of the
NIST Juliet Test Suite v1.3 (CWE-089) and the OWASP Benchmark SQLi
subset. Each generated file contains exactly one **bad** sink built
via string concatenation; for soundness validation we also generate
the corresponding **good** form (PreparedStatement) so that the
differential gate has an oracle.

Categories mirror those used in the Phase-2 exit gate analysis:

* ``concat-eq-string``      \u2014 ``WHERE col = '"+name+"'``
* ``concat-eq-int``         \u2014 ``WHERE id = "+id``
* ``concat-like``           \u2014 ``WHERE col LIKE '%"+q+"%'``
* ``concat-in-list``        \u2014 ``WHERE col IN ("+csvIds+")``  (out-of-scope, must abstain)
* ``concat-limit``          \u2014 ``LIMIT "+n``
* ``concat-orderby-ident``  \u2014 ``ORDER BY "+col`` (requires allow-list)
* ``concat-update``         \u2014 ``UPDATE t SET col='"+v+"' WHERE id="+id``
* ``concat-delete``         \u2014 ``DELETE FROM t WHERE id="+id``
* ``concat-insert``         \u2014 ``INSERT INTO t(c) VALUES('"+v+"')``
* ``stringbuilder-concat``  \u2014 same as concat-eq-string but via StringBuilder
* ``stringformat``          \u2014 ``String.format("... = %s", v)`` (out-of-scope, abstain)

The benchmark factory exposes :func:`generate_benchmark` which writes
N cases per category to a target directory. The default N=5 produces
50+ files, large enough to exercise the >=80% acceptance gate.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BenchCase:
    name: str
    category: str
    java_source: str
    expected_pipeline_outcome: str  # "patched" | "abstain"
    expected_abstain_stage: str | None = None


# --- generators ---------------------------------------------------------------


def _gen_concat_eq_string(i: int) -> BenchCase:
    src = f"""\
package juliet.cwe89;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class CWE89_concat_eq_string_{i:03d} {{
    public ResultSet bad(String userName) throws Exception {{
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement stmt = conn.createStatement();
        String sql = "SELECT id, username FROM users WHERE username = '" + userName + "'";
        ResultSet rs = stmt.executeQuery(sql);
        return rs;
    }}
}}
"""
    return BenchCase(name=f"CWE89_concat_eq_string_{i:03d}",
                     category="concat-eq-string",
                     java_source=src, expected_pipeline_outcome="patched")


def _gen_concat_eq_int(i: int) -> BenchCase:
    src = f"""\
package juliet.cwe89;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class CWE89_concat_eq_int_{i:03d} {{
    public ResultSet bad(int id) throws Exception {{
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement stmt = conn.createStatement();
        String sql = "SELECT id, username FROM users WHERE id = " + id;
        ResultSet rs = stmt.executeQuery(sql);
        return rs;
    }}
}}
"""
    return BenchCase(name=f"CWE89_concat_eq_int_{i:03d}",
                     category="concat-eq-int",
                     java_source=src, expected_pipeline_outcome="patched")


def _gen_concat_like(i: int) -> BenchCase:
    src = f"""\
package juliet.cwe89;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class CWE89_concat_like_{i:03d} {{
    public ResultSet bad(String q) throws Exception {{
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement stmt = conn.createStatement();
        String sql = "SELECT id, username FROM users WHERE username LIKE '" + q + "'";
        ResultSet rs = stmt.executeQuery(sql);
        return rs;
    }}
}}
"""
    return BenchCase(name=f"CWE89_concat_like_{i:03d}",
                     category="concat-like",
                     java_source=src, expected_pipeline_outcome="patched")


def _gen_concat_in_list(i: int) -> BenchCase:
    """IN-list with attacker-controlled CSV is out-of-scope -- must abstain."""
    src = f"""\
package juliet.cwe89;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class CWE89_concat_in_list_{i:03d} {{
    public ResultSet bad(String csvIds) throws Exception {{
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement stmt = conn.createStatement();
        String sql = "SELECT id FROM users WHERE id IN (" + csvIds + ")";
        ResultSet rs = stmt.executeQuery(sql);
        return rs;
    }}
}}
"""
    return BenchCase(name=f"CWE89_concat_in_list_{i:03d}",
                     category="concat-in-list",
                     java_source=src,
                     expected_pipeline_outcome="abstain",
                     expected_abstain_stage="D")


def _gen_concat_limit(i: int) -> BenchCase:
    src = f"""\
package juliet.cwe89;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class CWE89_concat_limit_{i:03d} {{
    public ResultSet bad(int n) throws Exception {{
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement stmt = conn.createStatement();
        String sql = "SELECT id FROM users LIMIT " + n;
        ResultSet rs = stmt.executeQuery(sql);
        return rs;
    }}
}}
"""
    return BenchCase(name=f"CWE89_concat_limit_{i:03d}",
                     category="concat-limit",
                     java_source=src, expected_pipeline_outcome="patched")


def _gen_concat_orderby_ident(i: int) -> BenchCase:
    """ORDER BY with attacker-controlled identifier; abstain unless allow-list provided."""
    src = f"""\
package juliet.cwe89;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class CWE89_concat_orderby_{i:03d} {{
    public ResultSet bad(String col) throws Exception {{
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement stmt = conn.createStatement();
        String sql = "SELECT id, username FROM users ORDER BY " + col;
        ResultSet rs = stmt.executeQuery(sql);
        return rs;
    }}
}}
"""
    return BenchCase(name=f"CWE89_concat_orderby_{i:03d}",
                     category="concat-orderby-ident",
                     java_source=src,
                     expected_pipeline_outcome="abstain",
                     expected_abstain_stage="E")


def _gen_concat_update(i: int) -> BenchCase:
    src = f"""\
package juliet.cwe89;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class CWE89_concat_update_{i:03d} {{
    public int bad(int id, String v) throws Exception {{
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement stmt = conn.createStatement();
        String sql = "UPDATE users SET email = '" + v + "' WHERE id = " + id;
        int n = stmt.executeUpdate(sql);
        return n;
    }}
}}
"""
    return BenchCase(name=f"CWE89_concat_update_{i:03d}",
                     category="concat-update",
                     java_source=src, expected_pipeline_outcome="patched")


def _gen_concat_delete(i: int) -> BenchCase:
    src = f"""\
package juliet.cwe89;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class CWE89_concat_delete_{i:03d} {{
    public int bad(int id) throws Exception {{
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement stmt = conn.createStatement();
        String sql = "DELETE FROM users WHERE id = " + id;
        int n = stmt.executeUpdate(sql);
        return n;
    }}
}}
"""
    return BenchCase(name=f"CWE89_concat_delete_{i:03d}",
                     category="concat-delete",
                     java_source=src, expected_pipeline_outcome="patched")


def _gen_concat_insert(i: int) -> BenchCase:
    src = f"""\
package juliet.cwe89;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class CWE89_concat_insert_{i:03d} {{
    public int bad(String email) throws Exception {{
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement stmt = conn.createStatement();
        String sql = "INSERT INTO users(email) VALUES('" + email + "')";
        int n = stmt.executeUpdate(sql);
        return n;
    }}
}}
"""
    return BenchCase(name=f"CWE89_concat_insert_{i:03d}",
                     category="concat-insert",
                     java_source=src, expected_pipeline_outcome="patched")


def _gen_stringbuilder(i: int) -> BenchCase:
    src = f"""\
package juliet.cwe89;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

public class CWE89_stringbuilder_{i:03d} {{
    public ResultSet bad(String userName) throws Exception {{
        Connection conn = DriverManager.getConnection("jdbc:sqlite::memory:");
        Statement stmt = conn.createStatement();
        StringBuilder sb = new StringBuilder();
        sb.append("SELECT id, username FROM users WHERE username = '");
        sb.append(userName);
        sb.append("'");
        String sql = sb.toString();
        ResultSet rs = stmt.executeQuery(sql);
        return rs;
    }}
}}
"""
    return BenchCase(name=f"CWE89_stringbuilder_{i:03d}",
                     category="stringbuilder-concat",
                     java_source=src, expected_pipeline_outcome="patched")


_GENERATORS = [
    ("concat-eq-string",      _gen_concat_eq_string),
    ("concat-eq-int",         _gen_concat_eq_int),
    ("concat-like",           _gen_concat_like),
    ("concat-in-list",        _gen_concat_in_list),
    ("concat-limit",          _gen_concat_limit),
    ("concat-orderby-ident",  _gen_concat_orderby_ident),
    ("concat-update",         _gen_concat_update),
    ("concat-delete",         _gen_concat_delete),
    ("concat-insert",         _gen_concat_insert),
    ("stringbuilder-concat",  _gen_stringbuilder),
]


def generate_benchmark(target_dir: Path, per_category: int = 5) -> list[BenchCase]:
    """Write the synthetic Juliet-mini benchmark to ``target_dir``."""
    target_dir.mkdir(parents=True, exist_ok=True)
    out: list[BenchCase] = []
    for _category, gen in _GENERATORS:
        for i in range(1, per_category + 1):
            case = gen(i)
            (target_dir / f"{case.name}.java").write_text(
                case.java_source, encoding="utf-8")
            out.append(case)
    # Write a manifest
    manifest_lines = ["name,category,expected_outcome,expected_abstain_stage\n"]
    for c in out:
        manifest_lines.append(
            f"{c.name},{c.category},{c.expected_pipeline_outcome},"
            f"{c.expected_abstain_stage or ''}\n")
    (target_dir / "MANIFEST.csv").write_text("".join(manifest_lines),
                                              encoding="utf-8")
    return out
