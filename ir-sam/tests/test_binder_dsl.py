"""Tests for the binding-catalog DSL loader."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from core.binder import ClosureViolation, load_catalog

CATALOG_PATH = Path(__file__).resolve().parents[1] / "binders" / "sql_jdbc.yaml"


def test_sql_jdbc_catalog_loads() -> None:
    cat = load_catalog(CATALOG_PATH)
    assert cat.id == "sql-jdbc"
    assert cat.interpreter == "sql"
    assert cat.host_language == "java"
    assert cat.framework == "jdbc"
    assert "java.sql.PreparedStatement.setString" in cat.parameterizing_apis
    ids = {b.id for b in cat.binders}
    # the five MVP binders are present
    assert {"sql-eq-value", "sql-like-value", "sql-in-list",
            "sql-limit-offset", "sql-orderby-ident"} <= ids


def test_closure_violation_is_rejected(tmp_path: Path) -> None:
    """A binder using an api not in parameterizing_apis must be rejected."""
    src = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    # tamper: change the like binder to use an external API
    for b in src["catalog"]["binders"]:
        if b["id"] == "sql-like-value":
            b["rewrite"]["bindings"][0]["api"] = "java.lang.Runtime.exec"
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump(src), encoding="utf-8")
    with pytest.raises(ClosureViolation):
        load_catalog(bad)


def test_unknown_binding_kind_rejected(tmp_path: Path) -> None:
    src = yaml.safe_load(CATALOG_PATH.read_text(encoding="utf-8"))
    for b in src["catalog"]["binders"]:
        if b["id"] == "sql-orderby-ident":
            b["rewrite"]["bindings"][0]["kind"] = "raw_concat"
    bad = tmp_path / "bad.yaml"
    bad.write_text(yaml.safe_dump(src), encoding="utf-8")
    with pytest.raises(Exception):
        load_catalog(bad)
