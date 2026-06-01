"""End-to-end pipeline tests for the Phase 4 Java backends.

Covers Shell (CWE-78), LDAP (CWE-90) and XPath (CWE-643) for the Java
host, driven through the generalized non-SQL slicer
(:mod:`core.slicer.nonsql`) and the ``parse_template`` seam. Each test
runs the full A..G pipeline and asserts the sound, structural patch was
produced (argv vector / RFC-4515 escaping / ``$vN`` variable binding).
"""

from pathlib import Path

import pytest

from core.ingest.unified import IRSAMFinding, Location, Sink
from core.pipeline import run_finding
from core.pipeline.dispatch import get_backend, supported_backends


def _make_finding(file: str, line: int, interp: str, cwe: str, api: str) -> IRSAMFinding:
    return IRSAMFinding(
        finding_id=f"t-java-{interp}",
        detector="semgrep",
        detector_rule_id=f"java.{interp}.injection",
        cwe=(cwe,),
        language="java",
        interpreter=interp,
        location=Location(file=file, line_start=line),
        sink=Sink(api_qualified_name=api, tainted_arg_indices=(0,)),
    )


def _sink_line(src: str, needle: str) -> int:
    for i, line in enumerate(src.splitlines(), start=1):
        if needle in line:
            return i
    raise AssertionError(f"sink {needle!r} not found")


def _run(tmp_path: Path, src: str, needle: str, interp: str, cwe: str, api: str):
    f = tmp_path / "Vuln.java"
    f.write_text(src, encoding="utf-8")
    finding = _make_finding(str(f), _sink_line(src, needle), interp, cwe, api)
    return run_finding(tmp_path, finding)


# --------------------------------------------------------------------------- #
# Registration                                                                #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("interp", ["shell", "ldap", "xpath"])
def test_java_backend_registered(interp):
    assert ("java", interp) in supported_backends()
    be = get_backend("java", interp)
    assert be is not None
    assert be.language == "java"
    assert be.interpreter == interp
    assert be.parse_template is not None


# --------------------------------------------------------------------------- #
# Shell (CWE-78)                                                              #
# --------------------------------------------------------------------------- #

_SHELL_VULN = '''\
public class Vuln {
    void run(String host) throws Exception {
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }
}
'''


def test_java_shell_end_to_end(tmp_path: Path):
    out = _run(tmp_path, _SHELL_VULN, ".exec(", "shell",
               "CWE-78", "java.lang.Runtime.exec")
    assert out.stage_reached == "G", (
        f"abstained at {out.stage_reached}: {out.abstention_reason}")
    patched = out.patch.patched_source
    assert "Runtime.getRuntime().exec" not in patched
    assert 'new ProcessBuilder("ping", "-c", "1", host).start()' in patched


_SHELL_MIDTOKEN = '''\
public class Vuln {
    void run(String host) throws Exception {
        Runtime.getRuntime().exec("ls -" + host);
    }
}
'''


def test_java_shell_midtoken_abstains(tmp_path: Path):
    out = _run(tmp_path, _SHELL_MIDTOKEN, ".exec(", "shell",
               "CWE-78", "java.lang.Runtime.exec")
    assert out.stage_reached != "G"


# --------------------------------------------------------------------------- #
# LDAP (CWE-90)                                                               #
# --------------------------------------------------------------------------- #

_LDAP_VULN = '''\
public class Vuln {
    void find(javax.naming.directory.DirContext ctx, String username) throws Exception {
        ctx.search("dc=example,dc=com", "(uid=" + username + ")", null);
    }
}
'''


def test_java_ldap_end_to_end(tmp_path: Path):
    out = _run(tmp_path, _LDAP_VULN, ".search(", "ldap",
               "CWE-90", "javax.naming.directory.DirContext.search")
    assert out.stage_reached == "G", (
        f"abstained at {out.stage_reached}: {out.abstention_reason}")
    patched = out.patch.patched_source
    assert "encodeForLDAP(username)" in patched
    assert "+ username +" not in patched


# --------------------------------------------------------------------------- #
# XPath (CWE-643)                                                             #
# --------------------------------------------------------------------------- #

_XPATH_VULN = '''\
public class Vuln {
    void find(javax.xml.xpath.XPath xp, org.w3c.dom.Document doc, String name) throws Exception {
        xp.evaluate("//user[@name='" + name + "']", doc);
    }
}
'''


def test_java_xpath_end_to_end(tmp_path: Path):
    out = _run(tmp_path, _XPATH_VULN, ".evaluate(", "xpath",
               "CWE-643", "javax.xml.xpath.XPath.evaluate")
    assert out.stage_reached == "G", (
        f"abstained at {out.stage_reached}: {out.abstention_reason}")
    patched = out.patch.patched_source
    assert "$v0" in patched
    assert "setXPathVariableResolver" in patched
    assert "@name='" not in patched
    assert "+ name +" not in patched
