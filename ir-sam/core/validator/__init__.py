"""Stage G --- the 5-gate validator.

For each candidate patch the validator runs five independent gates:

1.  **Compile gate.** If ``javac`` is available on PATH, run it on the
    patched file in a temp dir. If not, run a structural Java syntax
    check based on token-level brace balance and the absence of
    obviously broken constructs.

2.  **Regression gate.** If a project test runner is configured, run
    a minimal smoke check. In the MVP reference impl this is a no-op
    (returns ``True`` with a "not configured" note); real projects
    plug a Maven/Gradle invocation here.

3.  **Structural gate.** Re-checks the soundness predicate
    :func:`core.iam.structurally_sound` over the realizations recorded
    by stage E.

4.  **Re-SAST gate.** Re-scans the patched source with a regex-based
    residual CWE-89 detector ("``Statement.executeQuery(<concat>)``"
    or "``.execute(\"...\" + ...)``"). A successful patch must leave
    *zero* residual matches.

5.  **Differential gate.** Treats SQLite (in-memory) as the
    interpreter oracle. Builds a small fixture schema, runs both
    *original* (concatenation) and *patched* (prepared) statements
    against a curated set of (i) benign payloads and (ii) classical
    SQLi attack payloads. Pass criteria:

    *   For every benign payload, the patched statement returns the
        same row-set / row-count as the original.
    *   For every attack payload, the patched statement either binds
        the payload as a value (returning 0 rows or rejecting on
        type) **or** raises a parameter-binding error; it must
        **never** execute additional statements / drop tables.

The validator returns a :class:`GateReport` with per-gate verdicts.
"""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from core.iam import HostRealization, IAM, structurally_sound


# --- report types -------------------------------------------------------------


@dataclass(frozen=True)
class GateOutcome:
    name: str
    passed: bool
    detail: str = ""


@dataclass(frozen=True)
class GateReport:
    file: str
    gates: tuple[GateOutcome, ...]
    overall_passed: bool

    def by_name(self, name: str) -> GateOutcome | None:
        for g in self.gates:
            if g.name == name:
                return g
        return None


# --- gate 1: compile ----------------------------------------------------------


def run_compile_gate(java_src: str, *, classname_hint: str | None = None) -> GateOutcome:
    classname = classname_hint or _extract_public_class(java_src) or "Patched"
    if shutil.which("javac") is None:
        ok, detail = _structural_java_check(java_src)
        return GateOutcome("compile", ok,
                           "javac not available; ran structural check: " + detail)
    with tempfile.TemporaryDirectory() as tmp:
        fp = Path(tmp) / f"{classname}.java"
        fp.write_text(java_src, encoding="utf-8")
        try:
            r = subprocess.run(
                ["javac", "-Xlint:none", str(fp)],
                capture_output=True, text=True, cwd=tmp, timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as e:
            return GateOutcome("compile", False, f"javac error: {e}")
        ok = r.returncode == 0
        return GateOutcome("compile", ok,
                           ("" if ok else r.stderr.strip()[:1000]))


def _extract_public_class(src: str) -> str | None:
    m = re.search(r"public\s+(?:abstract\s+|final\s+)?class\s+([A-Za-z_][\w]*)", src)
    if m:
        return m.group(1)
    m = re.search(r"\bclass\s+([A-Za-z_][\w]*)", src)
    return m.group(1) if m else None


def _structural_java_check(src: str) -> tuple[bool, str]:
    # remove strings, then count braces / parens
    stripped = re.sub(r'"(?:\\.|[^"\\])*"', '""', src)
    stripped = re.sub(r"'(?:\\.|[^'\\])*'", "''", stripped)
    stripped = re.sub(r"//[^\n]*", "", stripped)
    stripped = re.sub(r"/\*.*?\*/", "", stripped, flags=re.S)
    braces = stripped.count("{") - stripped.count("}")
    parens = stripped.count("(") - stripped.count(")")
    if braces != 0:
        return False, f"unbalanced braces: {braces}"
    if parens != 0:
        return False, f"unbalanced parens: {parens}"
    return True, "balanced"


# --- gate 2: regression -------------------------------------------------------


def run_regression_gate(project_dir: Path | None = None,
                        *,
                        strict: bool | None = None,
                        config: "RegressionConfig | None" = None,
                        ) -> GateOutcome:
    """Regression gate (Phase 7).

    Delegates to :mod:`core.validator.regression` for the actual
    detect-and-run logic. The gate operates in two modes:

    * **Legacy mode** (default, ``strict=False``) preserves the
      MVP-era behavior: silently pass when no project_dir or no
      manifest is found. Used by tests that exercise the validator
      without a real repo.
    * **Strict mode** (``strict=True`` or
      ``IRSAM_REGRESSION_STRICT=1``) returns a typed soft-fail
      ``TEST_REGRESSION_NOT_CONFIGURED`` when nothing is configured;
      this is the regime expected by Phase 9's honesty surface so
      that unverified patches surface as ``validated_only`` rather
      than ``proven``.
    """
    from core.validator.regression import (
        RegressionConfig,
        run_regression_gate as _run_strict,
    )

    if strict is None:
        strict = os.environ.get("IRSAM_REGRESSION_STRICT") == "1"

    if not strict:
        # Legacy silent-pass behaviour preserved for callers that
        # have not opted in to the honesty surface.
        if project_dir is None or not project_dir.exists():
            return GateOutcome("regression", True,
                               "no project regression runner configured")
        pom = project_dir / "pom.xml"
        if pom.exists() and shutil.which("mvn"):
            try:
                r = subprocess.run(["mvn", "-q", "test"], cwd=project_dir,
                                   capture_output=True, text=True, timeout=600)
                return GateOutcome("regression", r.returncode == 0,
                                   r.stdout[-1000:] + r.stderr[-1000:])
            except (OSError, subprocess.TimeoutExpired) as e:
                return GateOutcome("regression", False, f"mvn error: {e}")
        gradle = project_dir / "build.gradle"
        if gradle.exists() and shutil.which("gradle"):
            try:
                r = subprocess.run(["gradle", "-q", "test"], cwd=project_dir,
                                   capture_output=True, text=True, timeout=600)
                return GateOutcome("regression", r.returncode == 0, "")
            except (OSError, subprocess.TimeoutExpired) as e:
                return GateOutcome("regression", False, f"gradle error: {e}")
        return GateOutcome("regression", True, "no maven/gradle runner found")

    return _run_strict(project_dir, config or RegressionConfig())


# --- gate 3: structural -------------------------------------------------------


def run_structural_gate(iam: IAM, realizations: Iterable[HostRealization],
                        parameterizing_apis: set[str]) -> GateOutcome:
    ok, reasons = structurally_sound(iam, list(realizations), parameterizing_apis)
    return GateOutcome("structural", ok, "; ".join(reasons))


# --- gate 4: re-SAST (residual CWE-89) ----------------------------------------


_RESIDUAL_PATTERNS = [
    # Statement.execute*(<expr that contains "+">)
    re.compile(
        r"""
        \b(?:Statement|java\.sql\.Statement)\b[^;]*?
        \.\s*(?:executeQuery|executeUpdate|execute|addBatch)\s*\(
        [^)]*\+[^)]*\)
        """,
        re.VERBOSE | re.DOTALL,
    ),
    # someStmt.executeXxx(<expr with "+">)  -- generic, any receiver
    re.compile(
        r"""
        [A-Za-z_]\w*\s*\.\s*(?:executeQuery|executeUpdate|execute|addBatch)
        \s*\(\s*[^);]*"\s*\+
        """,
        re.VERBOSE | re.DOTALL,
    ),
    # Connection.prepareStatement("..." + <expr>)
    re.compile(
        r"""
        \.\s*prepareStatement\s*\(\s*[^)]*\+[^)]*\)
        """,
        re.VERBOSE | re.DOTALL,
    ),
]


def run_resast_gate(
    java_src: str,
    *,
    use_detectors: bool | None = None,
    language: str = "java",
    file_name: str = "Patched.java",
    rule_ids: tuple[str, ...] = (),
) -> GateOutcome:
    """Re-SAST gate.

    By default (``use_detectors=None``) this consults the
    ``IRSAM_RESAST_BACKEND`` environment variable; when set to
    ``"detectors"`` the patched source is re-scanned by the real
    Semgrep / CodeQL runners and the gate passes iff none of them
    report a residual finding whose rule id is in ``rule_ids`` (or any
    finding when ``rule_ids`` is empty). Otherwise we fall back to the
    regex-based scan that ships with the MVP.
    """
    if use_detectors is None:
        use_detectors = os.environ.get("IRSAM_RESAST_BACKEND") == "detectors"

    if use_detectors:
        return _run_resast_via_detectors(
            java_src,
            language=language,
            file_name=file_name,
            rule_ids=rule_ids,
        )

    hits = []
    for pat in _RESIDUAL_PATTERNS:
        for m in pat.finditer(java_src):
            snippet = m.group(0)
            # filter known-safe shapes:
            #   "..." + __irsam_g_<name>  (our identifier-allowlist concat)
            if "__irsam_g_" in snippet:
                continue
            hits.append(snippet.strip()[:200])
    ok = not hits
    return GateOutcome("re_sast", ok,
                       "no residual CWE-89 patterns" if ok
                       else f"{len(hits)} residual hit(s): {hits[:3]}")


_LANGUAGE_DEFAULT_FILENAME: dict[str, str] = {
    "java":       "Patched.java",
    "python":     "patched.py",
}


def _run_resast_via_detectors(
    source: str,
    *,
    language: str,
    file_name: str,
    rule_ids: tuple[str, ...],
) -> GateOutcome:
    """Re-scan ``source`` with real detectors and report residuals."""
    from core.detectors import DetectorOutcome, DetectorUnavailable
    from core.detectors.codeql_runner import CodeQLRunner
    from core.detectors.semgrep_runner import SemgrepRunner

    fname = file_name or _LANGUAGE_DEFAULT_FILENAME.get(language, "patched.txt")

    with tempfile.TemporaryDirectory(prefix="irsam-resast-") as td:
        wd = Path(td)
        (wd / fname).write_text(source, encoding="utf-8")

        runners = [SemgrepRunner(), CodeQLRunner()]
        all_findings = []
        skipped: list[str] = []
        ran: list[str] = []

        for r in runners:
            result = r.scan(wd, languages=(language,))
            if isinstance(result, DetectorUnavailable):
                skipped.append(f"{result.detector}:{result.reason}")
                continue
            if isinstance(result, DetectorOutcome):
                ran.append(result.detector)
                for f in result.findings:
                    if not rule_ids or f.detector_rule_id in rule_ids:
                        all_findings.append(f)

        if not ran:
            # All detectors unavailable → soft-fail with typed reason
            # rather than silent pass.
            return GateOutcome(
                "re_sast",
                False,
                "no detectors available: " + "; ".join(skipped),
            )

        ok = not all_findings
        if ok:
            detail = f"no residuals (detectors: {', '.join(ran)})"
        else:
            summary = [
                f"{f.detector}:{f.detector_rule_id}@{f.location.line_start}"
                for f in all_findings[:3]
            ]
            detail = (f"{len(all_findings)} residual finding(s) via "
                      f"{', '.join(ran)}: {summary}")
        return GateOutcome("re_sast", ok, detail)


# --- gate 5: differential -----------------------------------------------------


# Classical SQLi payloads. Each tuple is (label, value).
ATTACK_PAYLOADS_STRING: tuple[tuple[str, str], ...] = (
    ("classic-or",      "' OR '1'='1"),
    ("comment-rest",    "' OR '1'='1' --"),
    ("stacked-drop",    "'; DROP TABLE users; --"),
    ("union-leak",      "' UNION SELECT username, password FROM users --"),
    ("hex-tautology",   "x' OR 1=1#"),
    ("benign-tickmark", "O'Brien"),
)

BENIGN_PAYLOADS_STRING: tuple[str, ...] = (
    "alice", "bob", "user-42", "test", "Mary",
)

ATTACK_PAYLOADS_INT: tuple[tuple[str, str], ...] = (
    ("int-or-tautology", "1 OR 1=1"),
    ("int-union",        "0 UNION SELECT 1"),
)

BENIGN_PAYLOADS_INT: tuple[int, ...] = (1, 2, 42, 100, 999)


def _build_fixture(con: sqlite3.Connection) -> None:
    con.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT
        );
        INSERT INTO users (id, username, password, email) VALUES
          (1, 'alice', 'pw1', 'alice@example.com'),
          (2, 'bob',   'pw2', 'bob@example.com'),
          (3, 'mary',  'pw3', 'mary@example.com');
        CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price INTEGER
        );
        INSERT INTO products (id, name, price) VALUES
          (1, 'foo', 10), (2, 'bar', 20), (3, 'baz', 30);
        """
    )


def _count_statements(sql: str) -> int:
    """Count top-level statements (heuristic, ignores quoted ';')."""
    n = 0
    in_quote = False
    for ch in sql:
        if ch == "'" :
            in_quote = not in_quote
        elif ch == ";" and not in_quote:
            n += 1
    if sql.strip().rstrip(";"):
        n = max(n, 1)
    return n


def run_differential_gate(
    *,
    original_concat_template: str,  # e.g. "SELECT * FROM users WHERE name = '{p}'"
    patched_prepared_template: str,  # e.g. "SELECT * FROM users WHERE name = ?"
    param_kind: str = "string",  # "string" or "integer"
) -> GateOutcome:
    """Run patched vs original on attack+benign payloads on SQLite.

    The original template uses Python ``str.format`` placeholders
    ``{p}``; the patched template uses SQL ``?``. The gate succeeds
    iff: (a) on every benign payload, patched and original return the
    same row-set; (b) on every attack payload, the patched statement
    does *not* produce a behavior outside ``Intent(A)`` (no extra
    statements executed; no schema mutation).
    """
    attack = ATTACK_PAYLOADS_STRING if param_kind == "string" else ATTACK_PAYLOADS_INT
    benign = BENIGN_PAYLOADS_STRING if param_kind == "string" else BENIGN_PAYLOADS_INT

    failures: list[str] = []

    # Benign equivalence
    for v in benign:
        con_o = sqlite3.connect(":memory:")
        con_p = sqlite3.connect(":memory:")
        _build_fixture(con_o)
        _build_fixture(con_p)
        try:
            orig_sql = original_concat_template.format(p=v)
            try:
                rows_o = con_o.execute(orig_sql).fetchall()
            except sqlite3.Error:
                rows_o = None
            try:
                rows_p = con_p.execute(patched_prepared_template, (v,)).fetchall()
            except sqlite3.Error as e:
                failures.append(f"benign:{v!r} patched-error: {e}")
                continue
            if rows_o is not None and rows_o != rows_p:
                failures.append(
                    f"benign:{v!r} rowset diverged: orig={rows_o} patched={rows_p}"
                )
        finally:
            con_o.close()
            con_p.close()

    # Attack: must not mutate schema in patched form.
    for label, v in attack:
        con_p = sqlite3.connect(":memory:")
        _build_fixture(con_p)
        try:
            try:
                con_p.execute(patched_prepared_template, (v,)).fetchall()
            except sqlite3.Error:
                pass  # benign -- attacker payload rejected by binding
            # Verify schema unchanged:
            schema = con_p.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
            tables = {r[0] for r in schema}
            if "users" not in tables or "products" not in tables:
                failures.append(f"attack:{label} mutated schema! tables={tables}")
        finally:
            con_p.close()

    ok = not failures
    detail = ("benign+attack equivalence holds"
              if ok else "; ".join(failures[:5]))
    return GateOutcome("differential", ok, detail)


# --- composite ---------------------------------------------------------------


def run_all_gates(
    *,
    file: str,
    patched_source: str,
    iam: IAM,
    realizations: Iterable[HostRealization],
    parameterizing_apis: set[str],
    original_concat_template: str | None = None,
    patched_prepared_template: str | None = None,
    param_kind: str = "string",
    project_dir: Path | None = None,
    language: str = "java",
) -> GateReport:
    gates: list[GateOutcome] = []
    gates.append(run_compile_gate(patched_source))
    gates.append(run_regression_gate(project_dir))
    gates.append(run_structural_gate(iam, realizations, parameterizing_apis))
    gates.append(run_resast_gate(patched_source, language=language))
    if original_concat_template is not None and patched_prepared_template is not None:
        gates.append(run_differential_gate(
            original_concat_template=original_concat_template,
            patched_prepared_template=patched_prepared_template,
            param_kind=param_kind,
        ))
    overall = all(g.passed for g in gates)
    return GateReport(file=file, gates=tuple(gates), overall_passed=overall)
