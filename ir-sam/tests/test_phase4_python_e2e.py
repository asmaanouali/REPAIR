"""End-to-end pipeline tests for the Phase 4 Python backends.

Covers the three non-SQL interpreters wired through the
``parse_template`` seam: Shell (CWE-78), LDAP (CWE-90) and XPath
(CWE-643). Each test drives the full A..G pipeline via
:func:`run_finding` and asserts the rewriter produced a sound,
parameterized patch (or abstained when the intent is unsafe to
prove).
"""

from pathlib import Path

import pytest

from core.ingest.unified import IRSAMFinding, Location, Sink
from core.pipeline import run_finding
from core.pipeline.dispatch import get_backend, supported_backends


def _make_finding(file: str, line: int, interp: str, cwe: str, api: str) -> IRSAMFinding:
    return IRSAMFinding(
        finding_id=f"t-py-{interp}",
        detector="semgrep",
        detector_rule_id=f"python.{interp}.injection",
        cwe=(cwe,),
        language="python",
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
    f = tmp_path / "vuln.py"
    f.write_text(src, encoding="utf-8")
    finding = _make_finding(str(f), _sink_line(src, needle), interp, cwe, api)
    return run_finding(tmp_path, finding)


# --------------------------------------------------------------------------- #
# Registration                                                                #
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("interp", ["shell", "ldap", "xpath"])
def test_python_backend_registered(interp):
    assert ("python", interp) in supported_backends()
    be = get_backend("python", interp)
    assert be is not None
    assert be.language == "python"
    assert be.interpreter == interp
    assert be.parse_template is not None


# --------------------------------------------------------------------------- #
# Shell (CWE-78)                                                              #
# --------------------------------------------------------------------------- #

_SHELL_VULN = '''\
import subprocess


def run_ping(host):
    subprocess.run("ping -c 1 " + host, shell=True)
'''


def test_python_shell_end_to_end(tmp_path: Path):
    out = _run(tmp_path, _SHELL_VULN, "subprocess.run", "shell",
               "CWE-78", "subprocess.run")
    assert out.stage_reached == "G", (
        f"abstained at {out.stage_reached}: {out.abstention_reason}")
    patched = out.patch.patched_source
    assert "shell=True" not in patched
    assert "shell=False" in patched
    assert "['ping', '-c', '1', host]" in patched


_SHELL_OS_SYSTEM = '''\
import os


def run_ping(host):
    os.system("ping -c 1 " + host)
'''


def test_python_shell_os_system_to_subprocess(tmp_path: Path):
    out = _run(tmp_path, _SHELL_OS_SYSTEM, "os.system", "shell",
               "CWE-78", "os.system")
    assert out.stage_reached == "G", (
        f"abstained at {out.stage_reached}: {out.abstention_reason}")
    patched = out.patch.patched_source
    assert "subprocess.call(['ping', '-c', '1', host])" in patched
    assert "import subprocess" in patched


_SHELL_MIDTOKEN = '''\
import subprocess


def run(host):
    subprocess.run("ls -" + host, shell=True)
'''


def test_python_shell_midtoken_abstains(tmp_path: Path):
    # A variable spliced inside a word boundary ("-"+host) cannot be proven
    # to map to a single argv element, so the rewriter must abstain.
    out = _run(tmp_path, _SHELL_MIDTOKEN, "subprocess.run", "shell",
               "CWE-78", "subprocess.run")
    assert out.stage_reached != "G"


# --------------------------------------------------------------------------- #
# LDAP (CWE-90)                                                               #
# --------------------------------------------------------------------------- #

_LDAP_VULN = '''\
def find_user(conn, username):
    conn.search("dc=example,dc=com", "(uid=" + username + ")")
'''


def test_python_ldap_end_to_end(tmp_path: Path):
    out = _run(tmp_path, _LDAP_VULN, "conn.search", "ldap",
               "CWE-90", "ldap3.Connection.search")
    assert out.stage_reached == "G", (
        f"abstained at {out.stage_reached}: {out.abstention_reason}")
    patched = out.patch.patched_source
    assert "escape_filter_chars(username)" in patched
    assert "from ldap3.utils.conv import escape_filter_chars" in patched
    assert "+ username +" not in patched


# --------------------------------------------------------------------------- #
# XPath (CWE-643)                                                             #
# --------------------------------------------------------------------------- #

_XPATH_VULN = '''\
def find_user(tree, name):
    return tree.xpath("//user[@name='" + name + "']")
'''


def test_python_xpath_end_to_end(tmp_path: Path):
    out = _run(tmp_path, _XPATH_VULN, "tree.xpath", "xpath",
               "CWE-643", "lxml.etree._Element.xpath")
    assert out.stage_reached == "G", (
        f"abstained at {out.stage_reached}: {out.abstention_reason}")
    patched = out.patch.patched_source
    assert "$v0" in patched
    assert "v0=name" in patched
    # The bound variable must not remain quoted.
    assert "@name='" not in patched
    assert "+ name +" not in patched
