"""Semgrep SARIF -> IRSAMFinding adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from .sarif import (
    cwe_tags,
    iter_results,
    load_sarif,
    physical_location,
    rule_id_of,
)
from .unified import Evidence, IRSAMFinding, Location, Sink

SEMGREP_RULE_MAP: dict[str, tuple[str, str, int, str]] = {
    "java.lang.security.audit.formatted-sql-string.formatted-sql-string": (
        "sql", "java", 0, "java.sql.Statement.executeQuery"
    ),
    "python.lang.security.audit.formatted-sql-query.formatted-sql-query": (
        "sql", "python", 0, "sqlite3.Cursor.execute"
    ),
    "java.lang.security.audit.command-injection-process-builder.command-injection-process-builder": (
        "shell", "java", 0, "java.lang.ProcessBuilder.<init>"
    ),
    "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true": (
        "shell", "python", 0, "subprocess.run"
    ),
    "java.lang.security.audit.ldap-injection.ldap-injection": (
        "ldap", "java", 1, "javax.naming.directory.DirContext.search"
    ),
    "python.lang.security.audit.ldap-injection.ldap-injection": (
        "ldap", "python", 1, "ldap.ldapobject.LDAPObject.search_s"
    ),
    "java.lang.security.audit.xpath-injection.xpath-injection": (
        "xpath", "java", 0, "javax.xml.xpath.XPath.evaluate"
    ),
    "python.lang.security.audit.xpath-injection.xpath-injection": (
        "xpath", "python", 0, "lxml.etree._Element.xpath"
    ),
    # Taint-mode (inter-statement dataflow) rules.
    "java.lang.security.taint.servlet-sql-injection.servlet-sql-injection": (
        "sql", "java", 0, "java.sql.Statement.executeQuery"
    ),
    "java.lang.security.taint.servlet-command-injection.servlet-command-injection": (
        "shell", "java", 0, "java.lang.ProcessBuilder.<init>"
    ),
}


def _resolve_rule(rule_id: str) -> tuple[str, str, int, str] | None:
    """Resolve a Semgrep rule id to an IR-SAM (interpreter, language,
    arg_idx, sink_hint) tuple.

    Registry rules carry their canonical dotted id verbatim. Rules loaded
    from a local YAML file are namespaced by Semgrep with the config's
    path (e.g. ``configs.semgrep.java.lang.security...``), so an exact
    lookup misses. We therefore fall back to a suffix match against the
    known canonical ids.
    """
    direct = SEMGREP_RULE_MAP.get(rule_id)
    if direct is not None:
        return direct
    for canonical, value in SEMGREP_RULE_MAP.items():
        if rule_id.endswith(canonical):
            return value
    return None


def adapt(sarif_path: str | Path) -> Iterator[IRSAMFinding]:
    sarif = load_sarif(sarif_path)
    for run, result in iter_results(sarif):
        rule_id = rule_id_of(result)
        resolved = _resolve_rule(rule_id)
        if resolved is None:
            continue
        interpreter, language, arg_idx, sink_hint = resolved
        file, line_start, line_end = physical_location(result)
        rules = (run.get("tool", {}).get("driver", {}).get("rules", []) or [])
        rule_obj = next((r for r in rules if r.get("id") == rule_id), None)
        cwes = cwe_tags(result, rule_obj) or _default_cwe_for(interpreter)
        yield IRSAMFinding(
            finding_id=IRSAMFinding.compute_id("semgrep", rule_id, file, line_start, sink_hint),
            detector="semgrep",
            detector_rule_id=rule_id,
            cwe=tuple(cwes),
            language=language,  # type: ignore[arg-type]
            interpreter=interpreter,  # type: ignore[arg-type]
            location=Location(file=file, line_start=line_start, line_end=line_end),
            sink=Sink(api_qualified_name=sink_hint, tainted_arg_indices=(arg_idx,)),
            detector_version=run.get("tool", {}).get("driver", {}).get("semanticVersion"),
            evidence=Evidence(full_message=(result.get("message") or {}).get("text")),
        )


def _default_cwe_for(interpreter: str) -> list[str]:
    return {
        "sql": ["CWE-89"], "shell": ["CWE-78"], "html-dom": ["CWE-79"],
        "ldap": ["CWE-90"], "xpath": ["CWE-643"], "path": ["CWE-22"],
        "template": ["CWE-1336"],
    }.get(interpreter, [])
