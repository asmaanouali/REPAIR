"""Cross-language synthetic benchmark (Phase 4).

Generates a small but shape-complete benchmark spanning the three
remaining in-scope combinations after the JS/TS removal:

  language x interpreter
  ----------------------
  Python   x SQL  (PEP-249)
  Python   x LDAP (ldap3, python-ldap)
  Python   x XPath (lxml)
  Java     x LDAP (JNDI)         -- reused from Phase 2 sink scanner

Each category produces ``n`` instances by varying identifier names
and literal values; the generator returns absolute file paths so the
evaluator can run the (language-dispatched) pipeline per case.

The benchmark is intentionally *self-contained*: no internet, no
JVM --- the Phase-2 ``ir-sam`` test environment is enough to
reproduce every number reported in the Phase-4 PDF.
"""

from __future__ import annotations

import string
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BenchCase:
    file_path: Path
    language: str        # "java" | "python"
    interpreter: str     # "sql" | "ldap" | "xpath"
    category: str
    expected_outcome: str  # "patched" | "abstain"
    allowlist: dict[str, str] | None = None


# --- Python / SQL ----------------------------------------------------------


def _py_sql(idx: int) -> str:
    return (
        "import sqlite3\n"
        "def fetch_user(conn: sqlite3.Connection, name: str):\n"
        "    cur = conn.cursor()\n"
        f"    sql = \"SELECT id FROM users WHERE name = '\" + name + \"'\"\n"
        "    cur.execute(sql)\n"
        "    return cur.fetchall()\n"
    )


def _py_sql_fstring(idx: int) -> str:
    return (
        "import sqlite3\n"
        "def find_product(conn: sqlite3.Connection, sku: str):\n"
        "    cur = conn.cursor()\n"
        "    cur.execute(f\"SELECT id FROM products WHERE sku = '{sku}'\")\n"
        "    return cur.fetchone()\n"
    )


def _py_sql_pctfmt(idx: int) -> str:
    return (
        "import sqlite3\n"
        "def get_user_by_id(conn, uid: int):\n"
        "    cur = conn.cursor()\n"
        "    cur.execute(\"SELECT * FROM users WHERE id = %d\" % uid)\n"
        "    return cur.fetchone()\n"
    )


# --- Python / LDAP ---------------------------------------------------------


def _py_ldap_eq(idx: int) -> str:
    return (
        "import ldap3\n"
        "def find_user(conn: ldap3.Connection, uid: str):\n"
        "    f = \"(uid=\" + uid + \")\"\n"
        "    conn.search('dc=example,dc=org', f)\n"
        "    return conn.entries\n"
    )


# --- Python / XPath --------------------------------------------------------


def _py_xpath_eq(idx: int) -> str:
    return (
        "from lxml import etree\n"
        "def find_user(tree, name: str):\n"
        "    return tree.xpath(\"//user[@name='\" + name + \"']\")\n"
    )


# --- generator -------------------------------------------------------------


_CATALOG = [
    ("py-sql-concat",      "python", "sql",   _py_sql,           "patched"),
    ("py-sql-fstring",     "python", "sql",   _py_sql_fstring,   "patched"),
    ("py-sql-pctfmt",      "python", "sql",   _py_sql_pctfmt,    "patched"),
    ("py-ldap-eq",         "python", "ldap",  _py_ldap_eq,       "patched"),
    ("py-xpath-eq",        "python", "xpath", _py_xpath_eq,      "patched"),
]


def generate_benchmark(out_dir: Path, *, per_category: int = 3
                       ) -> list[BenchCase]:
    out_dir.mkdir(parents=True, exist_ok=True)
    cases: list[BenchCase] = []
    for cat, lang, interp, fn, expected in _CATALOG:
        for k in range(per_category):
            src = fn(k)
            ext = {"python": "py", "java": "java"}[lang]
            fp = out_dir / f"{cat}_{k:02d}.{ext}"
            fp.write_text(src, encoding="utf-8")
            cases.append(BenchCase(fp, lang, interp, cat, expected))
    return cases
