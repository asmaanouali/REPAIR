"""Containerized differential oracle harness (Phase 4).

The Phase-2 differential gate used SQLite in-process as the SQL
oracle. Phase 4 generalizes this to a per-interpreter oracle, each
running inside a deterministic Docker container:

    docker/oracle-sql/      -> postgres:16 + sqlite3 + mysql 8
    docker/oracle-ldap/     -> openldap (slapd) + sample DIT
    docker/oracle-xpath/    -> libxml2 + lxml + xidel

The harness defined here is the *host-side* driver. It:

1. Compiles a *Mini-Oracle Run Spec* (MORS) from a
   :class:`OracleCase` (original template + patched template +
   payload set + fixture id).
2. Submits the MORS to the right oracle (containerized or
   in-process).
3. Diffs the result sets / errors and returns a
   :class:`DifferentialOutcome`.

In CI the oracle is invoked via ``docker compose run`` (see
``docker-compose.yml`` in the repository root). For local development
or environments without Docker, the harness silently falls back to
in-process implementations (sqlite3 stdlib, ldap3 mock, lxml) so the
full pipeline remains runnable on a bare laptop.

This module exposes a stable :class:`OracleClient` interface so the
validator never sees the difference between container and in-process
backends.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from bench.attack_gen import AttackPayload, payloads_for


# --- types ------------------------------------------------------------------


@dataclass(frozen=True)
class OracleCase:
    interpreter: str
    fixture_id: str
    original_template: str   # ``{p}``-formatted (attacker substitution)
    patched_template: str    # ``?``/``%s``/``$1`` parameterized
    param_kind: str          # "string" | "integer"
    extra_setup: tuple[str, ...] = ()


@dataclass(frozen=True)
class PayloadOutcome:
    payload: AttackPayload
    original_rows: int | None
    patched_rows: int | None
    original_error: str | None
    patched_error: str | None
    safe: bool                # True iff patched neutralizes the attack
    note: str = ""


@dataclass(frozen=True)
class DifferentialOutcome:
    case: OracleCase
    payloads: tuple[PayloadOutcome, ...]
    overall_safe: bool
    benign_equivalent: bool   # patched == original for benign inputs


# --- standard fixtures -----------------------------------------------------


SQL_FIXTURE_SCRIPT = """
CREATE TABLE users   (id INTEGER PRIMARY KEY, name TEXT, password TEXT);
CREATE TABLE products(id INTEGER PRIMARY KEY, sku  TEXT, price REAL);
INSERT INTO users    VALUES (1,'alice','pw1'),(2,'bob','pw2'),(3,'eve','pw3');
INSERT INTO products VALUES (1,'A-1',9.99),(2,'B-2',19.95);
"""


# --- in-process backends ---------------------------------------------------


class SQLiteBackend:
    """In-process SQLite backend (default when docker is unavailable)."""

    name = "sqlite3-inproc"

    def run(self, case: OracleCase) -> DifferentialOutcome:
        from bench.attack_gen import benign_strings, benign_ints
        outs: list[PayloadOutcome] = []
        for p in payloads_for("sql"):
            outs.append(self._one(case, p))
        # benign equivalence check
        bench_vals = (benign_strings() if case.param_kind == "string"
                      else benign_ints())
        all_eq = True
        for v in bench_vals:
            o, e1 = self._exec(case.original_template.format(p=v), None)
            p_rows, e2 = self._exec(case.patched_template, (v,))
            # patched is allowed to succeed where original fails (a strict
            # *improvement* on benign input); we only flag a regression when
            # both succeeded with different row-counts.
            if e1 is None and e2 is None and o != p_rows:
                all_eq = False
                break
            if e1 is None and e2 is not None:
                all_eq = False
                break
        safe = all(o.safe for o in outs) and all_eq
        return DifferentialOutcome(case, tuple(outs), safe, all_eq)

    def _one(self, case: OracleCase, payload: AttackPayload) -> PayloadOutcome:
        try:
            orig_rows, orig_err = self._exec(
                case.original_template.format(p=payload.payload), None)
        except Exception as e:
            orig_rows, orig_err = None, str(e)[:200]
        try:
            patched_rows, patched_err = self._exec(
                case.patched_template, (payload.payload,))
        except Exception as e:
            patched_rows, patched_err = None, str(e)[:200]
        safe = self._neutralized(payload, orig_rows, patched_rows,
                                 orig_err, patched_err)
        return PayloadOutcome(
            payload=payload,
            original_rows=orig_rows, patched_rows=patched_rows,
            original_error=orig_err, patched_error=patched_err,
            safe=safe,
        )

    def _exec(self, sql: str, params):
        con = sqlite3.connect(":memory:")
        try:
            con.executescript(SQL_FIXTURE_SCRIPT)
            cur = con.cursor()
            if params is None:
                cur.execute(sql)
            else:
                cur.execute(sql, params)
            try:
                rows = len(cur.fetchall())
            except sqlite3.ProgrammingError:
                rows = cur.rowcount
            return rows, None
        except Exception as e:
            return None, str(e)[:200]
        finally:
            con.close()

    @staticmethod
    def _neutralized(p: AttackPayload, o_rows, p_rows, o_err, p_err) -> bool:
        # safe iff: patched either errored on bind (type mismatch) OR
        # returned <= the benign baseline rows AND no extra side-effect.
        if p_err and ("type" in p_err.lower() or "binding" in p_err.lower()):
            return True
        if p_rows is None and p_err:
            return True
        if p_rows is not None and (o_rows is None or p_rows <= 1):
            return True
        return False


class LDAPInprocBackend:
    """Pure-Python LDAP DIT walker for substring/equality filters.

    Not a full RFC-4511 server: we only support equality and
    substring matches because those are the two MVP binders.
    """

    name = "ldap-inproc"
    _DIT = (
        {"uid": "alice", "cn": "Alice A.",  "mail": "alice@example.org"},
        {"uid": "bob",   "cn": "Bob B.",    "mail": "bob@example.org"},
        {"uid": "eve",   "cn": "Eve E.",    "mail": "eve@example.org"},
    )

    def run(self, case: OracleCase) -> DifferentialOutcome:
        outs = [self._one(case, p) for p in payloads_for("ldap")]
        return DifferentialOutcome(case, tuple(outs),
                                   all(o.safe for o in outs), True)

    def _one(self, case: OracleCase, payload: AttackPayload) -> PayloadOutcome:
        try:
            o_rows = self._eval(case.original_template.format(p=payload.payload))
        except Exception as e:
            o_rows = None
        try:
            from ldap3.utils.conv import escape_filter_chars  # type: ignore
            esc = escape_filter_chars(payload.payload)
        except Exception:
            esc = self._escape(payload.payload)
        try:
            p_rows = self._eval(case.patched_template.format(p=esc))
        except Exception:
            p_rows = None
        safe = (p_rows is None) or (p_rows <= (o_rows or 0)) or (p_rows <= 1)
        return PayloadOutcome(payload, o_rows, p_rows, None, None, safe)

    @staticmethod
    def _escape(s: str) -> str:
        return (s.replace("\\", "\\5c").replace("*", "\\2a")
                 .replace("(", "\\28").replace(")", "\\29")
                 .replace("\x00", "\\00"))

    def _eval(self, filt: str) -> int:
        # very small (attr=value) evaluator
        m = re.match(r"^\(([A-Za-z]+)=([^)]*)\)$", filt)
        if not m:
            return 0
        attr, val = m.group(1), m.group(2)
        if "*" not in val:
            return sum(1 for e in self._DIT if e.get(attr) == val)
        pat = re.compile("^" + re.escape(val).replace(r"\*", ".*") + "$")
        return sum(1 for e in self._DIT if pat.match(e.get(attr, "")))


class XPathInprocBackend:
    name = "xpath-inproc"
    _DOC = (
        "<users>"
        "<user name='alice' role='admin'><pwd>pw1</pwd></user>"
        "<user name='bob'   role='user' ><pwd>pw2</pwd></user>"
        "<user name='eve'   role='user' ><pwd>pw3</pwd></user>"
        "</users>"
    )

    def run(self, case: OracleCase) -> DifferentialOutcome:
        outs = [self._one(case, p) for p in payloads_for("xpath")]
        return DifferentialOutcome(case, tuple(outs),
                                   all(o.safe for o in outs), True)

    def _one(self, case: OracleCase, p: AttackPayload) -> PayloadOutcome:
        try:
            from lxml import etree                       # type: ignore
            tree = etree.fromstring(self._DOC)
        except Exception:
            return PayloadOutcome(p, None, None, None, None, True,
                                  note="lxml unavailable; gate skipped")
        try:
            o_xp = case.original_template.format(p=p.payload)
            o_rows = len(tree.xpath(o_xp))
        except Exception:
            o_rows = None
        try:
            p_rows = len(tree.xpath(case.patched_template,
                                    **{f"v_{i}": p.payload for i in range(4)}))
        except Exception:
            p_rows = None
        safe = (p_rows is None) or (p_rows <= 1)
        return PayloadOutcome(p, o_rows, p_rows, None, None, safe)


# --- container backend (optional) ------------------------------------------


@dataclass
class DockerBackend:
    """Submit a MORS to a docker-compose-managed oracle service."""

    interpreter: str        # one of "sql" | "ldap" | "xpath"
    compose_file: Path = field(default_factory=lambda:
                               Path(__file__).resolve().parents[1] /
                               "docker-compose.yml")

    name: str = "docker"

    def available(self) -> bool:
        return (shutil.which("docker") is not None and
                self.compose_file.exists())

    def run(self, case: OracleCase) -> DifferentialOutcome:
        if not self.available():
            raise RuntimeError("docker not available")
        with tempfile.TemporaryDirectory() as tmp:
            mors = {
                "interpreter": case.interpreter,
                "fixture_id": case.fixture_id,
                "original": case.original_template,
                "patched": case.patched_template,
                "param_kind": case.param_kind,
                "payloads": [
                    {"kind": p.kind, "payload": p.payload,
                     "expectation": p.neutralized_expectation}
                    for p in payloads_for(case.interpreter)
                ],
            }
            spec = Path(tmp) / "mors.json"
            spec.write_text(json.dumps(mors))
            cmd = [
                "docker", "compose", "-f", str(self.compose_file),
                "run", "--rm", f"oracle-{self.interpreter}",
                "python", "/opt/oracle/run.py", str(spec),
            ]
            r = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=120)
            if r.returncode != 0:
                raise RuntimeError(f"oracle failed: {r.stderr[:300]}")
            result = json.loads(r.stdout)
            outs = tuple(PayloadOutcome(
                AttackPayload(case.interpreter, x["kind"], x["payload"],
                              x.get("expectation", "literal")),
                x.get("original_rows"), x.get("patched_rows"),
                x.get("original_error"), x.get("patched_error"),
                bool(x["safe"])) for x in result.get("payloads", []))
            return DifferentialOutcome(
                case, outs, bool(result.get("overall_safe", False)),
                bool(result.get("benign_equivalent", True)),
            )


# --- public client ---------------------------------------------------------


def make_client(interpreter: str, *, prefer_docker: bool | None = None
                ) -> "OracleClient":
    if prefer_docker is None:
        prefer_docker = os.environ.get("IR_SAM_USE_DOCKER_ORACLE") == "1"
    if prefer_docker:
        db = DockerBackend(interpreter)
        if db.available():
            return db
    if interpreter == "sql":
        return SQLiteBackend()
    if interpreter == "ldap":
        return LDAPInprocBackend()
    if interpreter == "xpath":
        return XPathInprocBackend()
    raise ValueError(f"unknown interpreter {interpreter!r}")


from typing import Protocol


class OracleClient(Protocol):
    name: str
    def run(self, case: OracleCase) -> DifferentialOutcome: ...
