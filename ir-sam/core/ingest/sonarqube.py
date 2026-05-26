"""SonarQube SARIF -> IRSAMFinding adapter.

SonarQube exports issues via its web API in a proprietary JSON format,
but also offers a SARIF export plugin used by enterprise installs. This
adapter reads the SARIF flavor; the alternative ``adapt_native`` reads
the SonarQube REST shape directly.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from .sarif import iter_results, load_sarif, physical_location, rule_id_of
from .unified import Evidence, IRSAMFinding, Location, Sink

SONAR_RULE_MAP: dict[str, tuple[str, str, str, int, str]] = {
    # rule_id -> (cwe, interpreter, language, tainted-arg-idx, sink hint)
    "javasecurity:S3649": ("CWE-89", "sql", "java", 0, "java.sql.Statement.executeQuery"),
    "pythonsecurity:S3649": ("CWE-89", "sql", "python", 0, "sqlite3.Cursor.execute"),
    "javasecurity:S2076": ("CWE-78", "shell", "java", 0, "java.lang.Runtime.exec"),
    "pythonsecurity:S4823": ("CWE-78", "shell", "python", 0, "subprocess.run"),
    "javasecurity:S5131": ("CWE-79", "html-dom", "java", 0, "javax.servlet.jsp.JspWriter.print"),
    "javasecurity:S2078": ("CWE-90", "ldap", "java", 0, "javax.naming.directory.DirContext.search"),
    "javasecurity:S2091": ("CWE-643", "xpath", "java", 0, "javax.xml.xpath.XPath.evaluate"),
}


def adapt(sarif_path: str | Path) -> Iterator[IRSAMFinding]:
    sarif = load_sarif(sarif_path)
    for run, result in iter_results(sarif):
        rid = rule_id_of(result)
        if rid not in SONAR_RULE_MAP:
            continue
        cwe, interpreter, language, arg_idx, sink_hint = SONAR_RULE_MAP[rid]
        file, line_start, line_end = physical_location(result)
        yield IRSAMFinding(
            finding_id=IRSAMFinding.compute_id("sonarqube", rid, file, line_start, sink_hint),
            detector="sonarqube",
            detector_rule_id=rid,
            cwe=(cwe,),
            language=language,  # type: ignore[arg-type]
            interpreter=interpreter,  # type: ignore[arg-type]
            location=Location(file=file, line_start=line_start, line_end=line_end),
            sink=Sink(api_qualified_name=sink_hint, tainted_arg_indices=(arg_idx,)),
            detector_version=run.get("tool", {}).get("driver", {}).get("semanticVersion"),
            evidence=Evidence(full_message=(result.get("message") or {}).get("text")),
        )


def adapt_native(json_path: str | Path) -> Iterator[IRSAMFinding]:
    """Adapt SonarQube REST API ``api/issues/search`` JSON dump."""
    data: dict[str, Any] = json.loads(Path(json_path).read_text(encoding="utf-8"))
    for issue in data.get("issues", []):
        rid = issue.get("rule", "")
        if rid not in SONAR_RULE_MAP:
            continue
        cwe, interpreter, language, arg_idx, sink_hint = SONAR_RULE_MAP[rid]
        file = issue.get("component", "<unknown>").split(":", 1)[-1]
        line_start = int(issue.get("line", 1))
        yield IRSAMFinding(
            finding_id=IRSAMFinding.compute_id("sonarqube", rid, file, line_start, sink_hint),
            detector="sonarqube",
            detector_rule_id=rid,
            cwe=(cwe,),
            language=language,  # type: ignore[arg-type]
            interpreter=interpreter,  # type: ignore[arg-type]
            location=Location(file=file, line_start=line_start),
            sink=Sink(api_qualified_name=sink_hint, tainted_arg_indices=(arg_idx,)),
            evidence=Evidence(full_message=issue.get("message")),
        )
