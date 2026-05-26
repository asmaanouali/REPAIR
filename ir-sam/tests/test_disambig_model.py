"""Unit tests for the Stage-D disambiguator policy machinery."""
from __future__ import annotations

import os

import pytest

from core.disambig import (
    Answer,
    HeuristicPolicy,
    ModelPolicy,
    Question,
    labels,
    load_default_policy,
)


# --- label schema invariants -----------------------------------------------


def test_label_schema_is_frozen():
    assert labels.SCHEMA_VERSION == "1"
    for ls in labels.all_label_sets():
        # All labels unique; first label is safest fallback.
        assert len(set(ls.labels)) == len(ls.labels)
        assert ls.safest_label == ls.labels[0]
        # Descriptions are aligned.
        assert len(ls.descriptions) == len(ls.labels)


def test_label_schema_lookup_unknown_site_raises():
    with pytest.raises(KeyError):
        labels.get("sql", "totally_made_up_site")


# --- heuristic policy regressions ------------------------------------------


def test_heuristic_sql_in_list_with_collection_host():
    ls = labels.SQL_IN_POSITION
    q = Question(
        sig_text="SELECT * FROM t WHERE id IN (<<H0>>)",
        context="java; host_type=java.util.List<Integer>",
        labels=ls.labels,
        interpreter="sql", site="in_position",
    )
    a = HeuristicPolicy().choose(q)
    assert a.label == "in_list_csv"
    assert a.source == "heuristic"
    assert 0.0 <= a.confidence <= 1.0


def test_heuristic_sql_in_list_with_scalar_host():
    ls = labels.SQL_IN_POSITION
    q = Question(
        sig_text="SELECT * FROM t WHERE id IN (<<H0>>)",
        context="java; host_type=String",
        labels=ls.labels,
        interpreter="sql", site="in_position",
    )
    a = HeuristicPolicy().choose(q)
    assert a.label == "string_value"


def test_heuristic_defaults_to_safest_label():
    q = Question(
        sig_text="something unrelated",
        context="",
        labels=("safe_option", "risky_option"),
    )
    a = HeuristicPolicy().choose(q)
    assert a.label == "safe_option"


def test_heuristic_rejects_empty_labels():
    with pytest.raises(ValueError):
        HeuristicPolicy().choose(Question(sig_text="x", context="", labels=()))


# --- model policy fallback (no checkpoint loadable) ------------------------


def test_model_policy_falls_back_to_heuristic_when_load_fails():
    # Point at a non-existent checkpoint; load must fail safely.
    pol = ModelPolicy("/nonexistent/checkpoint/abc123")
    q = Question(
        sig_text="SELECT * FROM t WHERE id IN (<<H0>>)",
        context="python; host_type=list[int]",
        labels=labels.SQL_IN_POSITION.labels,
        interpreter="sql", site="in_position",
    )
    a = pol.choose(q)
    assert isinstance(a, Answer)
    assert a.source == "model-fallback"
    # Fallback should still produce a registered label.
    assert a.label in labels.SQL_IN_POSITION.labels


def test_model_policy_prompt_template_stable():
    # The training corpus is generated against this exact template.
    # Changing it without bumping SCHEMA_VERSION breaks the checkpoint.
    q = Question(
        sig_text="SELECT 1",
        context="ctx",
        labels=("a", "b"),
        interpreter="sql", site="in_position",
    )
    prompt = ModelPolicy._build_prompt(q)
    assert "# IR-SAM SIG disambiguation" in prompt
    assert "# interpreter: sql" in prompt
    assert "# site: in_position" in prompt
    assert "# choose one of: a, b" in prompt
    assert prompt.endswith("answer: ")


# --- factory selection ------------------------------------------------------


def test_load_default_policy_heuristic_explicit(monkeypatch):
    monkeypatch.setenv("IR_SAM_DISAMBIG_POLICY", "heuristic")
    monkeypatch.setenv("IR_SAM_DISAMBIG_MODEL", "/some/path")
    pol = load_default_policy()
    assert type(pol).__name__ == "HeuristicPolicy"


def test_load_default_policy_auto_without_model(monkeypatch):
    monkeypatch.delenv("IR_SAM_DISAMBIG_POLICY", raising=False)
    monkeypatch.delenv("IR_SAM_DISAMBIG_MODEL", raising=False)
    pol = load_default_policy()
    assert type(pol).__name__ == "HeuristicPolicy"


def test_load_default_policy_model_forced_without_ckpt_warns(monkeypatch):
    monkeypatch.setenv("IR_SAM_DISAMBIG_POLICY", "model")
    monkeypatch.delenv("IR_SAM_DISAMBIG_MODEL", raising=False)
    with pytest.warns(UserWarning):
        pol = load_default_policy()
    assert type(pol).__name__ == "HeuristicPolicy"


def test_load_default_policy_auto_with_model_returns_model(monkeypatch):
    monkeypatch.setenv("IR_SAM_DISAMBIG_POLICY", "auto")
    monkeypatch.setenv("IR_SAM_DISAMBIG_MODEL", "/nonexistent/abc")
    pol = load_default_policy()
    assert type(pol).__name__ == "ModelPolicy"


# --- threshold env validation ----------------------------------------------


def test_threshold_default(monkeypatch):
    monkeypatch.delenv("IR_SAM_DISAMBIG_THRESHOLD", raising=False)
    pol = ModelPolicy("/nonexistent/abc")
    assert pol.threshold == 0.5


def test_threshold_parsed_from_env(monkeypatch):
    monkeypatch.setenv("IR_SAM_DISAMBIG_THRESHOLD", "0.75")
    pol = ModelPolicy("/nonexistent/abc")
    assert pol.threshold == 0.75


def test_threshold_out_of_range_warns_and_uses_default(monkeypatch):
    monkeypatch.setenv("IR_SAM_DISAMBIG_THRESHOLD", "2.5")
    with pytest.warns(UserWarning):
        pol = ModelPolicy("/nonexistent/abc")
    assert pol.threshold == 0.5


def test_threshold_unparseable_warns(monkeypatch):
    monkeypatch.setenv("IR_SAM_DISAMBIG_THRESHOLD", "not-a-float")
    with pytest.warns(UserWarning):
        pol = ModelPolicy("/nonexistent/abc")
    assert pol.threshold == 0.5
