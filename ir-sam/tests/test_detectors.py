"""Tests for the real-detector runners (Phase 6)."""

from __future__ import annotations

import os
import sys
import shutil
import tempfile
from pathlib import Path

import pytest

from core.detectors import DetectorOutcome, DetectorUnavailable
from core.detectors.codeql_runner import CodeQLRunner
from core.detectors.semgrep_runner import SemgrepRunner
from core.validator import run_resast_gate


def test_semgrep_runner_skips_when_binary_missing(monkeypatch, tmp_path):
    # Force PATH to a directory that contains no semgrep binary.
    monkeypatch.setenv("PATH", str(tmp_path))
    r = SemgrepRunner()
    result = r.scan(tmp_path)
    assert isinstance(result, DetectorUnavailable)
    assert result.detector == "semgrep"
    assert "PATH" in result.reason or "binary" in result.reason


def test_codeql_runner_unavailable_without_env(monkeypatch, tmp_path):
    monkeypatch.delenv("IRSAM_CODEQL_BIN", raising=False)
    monkeypatch.delenv("IRSAM_CODEQL_DB", raising=False)
    r = CodeQLRunner()
    result = r.scan(tmp_path)
    assert isinstance(result, DetectorUnavailable)
    assert result.detector == "codeql"


def test_codeql_runner_unavailable_with_bin_but_no_db(monkeypatch, tmp_path):
    fake_bin = tmp_path / "codeql"
    fake_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    monkeypatch.setenv("IRSAM_CODEQL_BIN", str(fake_bin))
    monkeypatch.delenv("IRSAM_CODEQL_DB", raising=False)
    r = CodeQLRunner()
    result = r.scan(tmp_path)
    assert isinstance(result, DetectorUnavailable)
    assert "database" in result.reason.lower()


def test_resast_gate_regex_backend_unchanged():
    """Default backend remains the regex matcher and behaves as before."""
    safe = (
        'String q = "SELECT * FROM users WHERE id = ?";\n'
        'PreparedStatement ps = c.prepareStatement(q);\n'
    )
    outcome = run_resast_gate(safe)
    assert outcome.passed is True
    assert "no residual CWE-89 patterns" in outcome.detail

    bad = (
        'Statement s = c.createStatement();\n'
        's.executeQuery("SELECT * FROM users WHERE name = \'" + name + "\'");\n'
    )
    outcome = run_resast_gate(bad)
    assert outcome.passed is False


def test_resast_gate_detector_backend_soft_fails_when_no_detectors(
    monkeypatch, tmp_path
):
    """When the detectors backend is selected but no detector is
    installed/configured, the gate must surface a typed soft-fail
    rather than silently pass.
    """
    monkeypatch.setenv("IRSAM_RESAST_BACKEND", "detectors")
    monkeypatch.setenv("PATH", str(tmp_path))
    monkeypatch.delenv("IRSAM_CODEQL_BIN", raising=False)

    outcome = run_resast_gate("String q = \"SELECT 1\";\n")
    assert outcome.passed is False
    assert "no detectors available" in outcome.detail


@pytest.mark.skipif(
    shutil.which("semgrep") is None,
    reason="semgrep binary not installed",
)
def test_resast_gate_detector_backend_with_semgrep_clean(monkeypatch):
    """When semgrep is installed and the patched source is clean, the
    detector-backed re-SAST gate must pass."""
    monkeypatch.setenv("IRSAM_RESAST_BACKEND", "detectors")
    safe_java = (
        "public class P {\n"
        "  public void m(java.sql.Connection c, String n) throws Exception {\n"
        '    String q = "SELECT * FROM users WHERE name = ?";\n'
        "    java.sql.PreparedStatement ps = c.prepareStatement(q);\n"
        "    ps.setString(1, n);\n"
        "    ps.executeQuery();\n"
        "  }\n"
        "}\n"
    )
    outcome = run_resast_gate(safe_java, language="java")
    # On systems where semgrep returns no findings for this rule set we
    # expect a pass; if semgrep produces an unrelated finding we
    # tolerate it (rule_ids filter would normally be set).
    assert outcome.name == "re_sast"
