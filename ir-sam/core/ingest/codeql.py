"""CodeQL SARIF -> IRSAMFinding adapter.

We only depend on CodeQL's standard SARIF output (``codeql database
analyze --format=sarif-latest``). Rule-id -> (CWE, interpreter, language,
sink-arg) mapping is **data** in :data:`CODEQL_RULE_MAP` so it can be
extended without code changes.
"""

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
from .unified import (
    Evidence,
    IRSAMFinding,
    Location,
    Sink,
)

# rule_id -> (interpreter, language, default tainted-arg index, sink api hint)
CODEQL_RULE_MAP: dict[str, tuple[str, str, int, str]] = {
    "java/sql-injection": ("sql", "java", 0, "java.sql.Statement.executeQuery"),
    "java/concatenated-sql-query": ("sql", "java", 0, "java.sql.Statement.executeQuery"),
    "py/sql-injection": ("sql", "python", 0, "sqlite3.Cursor.execute"),
    "java/command-line-injection": ("shell", "java", 0, "java.lang.Runtime.exec"),
    "py/command-line-injection": ("shell", "python", 0, "subprocess.run"),
    "java/xss": ("html-dom", "java", 0, "javax.servlet.jsp.JspWriter.print"),
    "java/ldap-injection": ("ldap", "java", 0, "javax.naming.directory.DirContext.search"),
    "java/xpath-injection": ("xpath", "java", 0, "javax.xml.xpath.XPath.evaluate"),
    "java/path-injection": ("path", "java", 0, "java.io.File.<init>"),
    "py/path-injection": ("path", "python", 0, "builtins.open"),
}


def adapt(sarif_path: str | Path) -> Iterator[IRSAMFinding]:
    sarif = load_sarif(sarif_path)
    for run, result in iter_results(sarif):
        rule_id = rule_id_of(result)
        if rule_id not in CODEQL_RULE_MAP:
            # skip out-of-scope rules silently; logged at a higher layer
            continue
        interpreter, language, arg_idx, sink_hint = CODEQL_RULE_MAP[rule_id]
        file, line_start, line_end = physical_location(result)
        # CodeQL emits CWE tags on the rule object inside tool.driver.rules
        rules = (run.get("tool", {}).get("driver", {}).get("rules", []) or [])
        rule_obj = next((r for r in rules if r.get("id") == rule_id), None)
        cwes = cwe_tags(result, rule_obj)
        if not cwes:
            cwes = _default_cwe_for(interpreter)
        yield IRSAMFinding(
            finding_id=IRSAMFinding.compute_id("codeql", rule_id, file, line_start, sink_hint),
            detector="codeql",
            detector_rule_id=rule_id,
            cwe=tuple(cwes),
            language=language,  # type: ignore[arg-type]
            interpreter=interpreter,  # type: ignore[arg-type]
            location=Location(file=file, line_start=line_start, line_end=line_end),
            sink=Sink(api_qualified_name=sink_hint, tainted_arg_indices=(arg_idx,)),
            detector_version=run.get("tool", {}).get("driver", {}).get("semanticVersion"),
            evidence=Evidence(
                full_message=(result.get("message") or {}).get("text"),
            ),
        )


def _default_cwe_for(interpreter: str) -> list[str]:
    return {
        "sql": ["CWE-89"],
        "shell": ["CWE-78"],
        "html-dom": ["CWE-79"],
        "ldap": ["CWE-90"],
        "xpath": ["CWE-643"],
        "template": ["CWE-1336"],
        "path": ["CWE-22"],
    }.get(interpreter, [])
