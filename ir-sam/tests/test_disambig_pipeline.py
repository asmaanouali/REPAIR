"""Integration tests for the Stage-D disambiguator wiring.

These tests pin down:

* the parser honors ``disambig_hints`` for the SQL IN-list ambiguity,
* the pipeline's helper builds a valid provenance dict,
* the corpus generator only emits labels that are registered in the schema.
"""
from __future__ import annotations

from core.disambig import labels as label_schema
from core.iam import Cardinality, Hole, SIGNode
from core.parsers import (
    SQL0AmbiguousIntent,
    parse_template_to_sig,
)
from core.recon import ParameterizedTemplate, TemplateHole


def _make_in_list_template() -> ParameterizedTemplate:
    """Concrete IN-list template with one attacker-controlled hole."""
    return ParameterizedTemplate(
        text="SELECT * FROM t WHERE id IN (<<H0>>)",
        holes=(
            TemplateHole(
                idx=0,
                host_expr="userIds",
                sem="string",
            ),
        ),
    )


def test_parser_abstains_on_in_list_without_hint():
    tpl = _make_in_list_template()
    try:
        parse_template_to_sig(tpl)
    except SQL0AmbiguousIntent:
        return
    raise AssertionError("expected SQL0AmbiguousIntent without hint")


def test_parser_promotes_to_many_bounded_with_in_list_csv_hint():
    tpl = _make_in_list_template()
    lift = parse_template_to_sig(tpl, disambig_hints={"h0": "in_list_csv"})
    assert len(lift.holes) == 1
    hole = lift.holes[0]
    assert isinstance(hole, Hole)
    assert hole.card == Cardinality.MANY_BOUNDED
    # The lift root should be a Select tree containing one InExpr.
    assert isinstance(lift.sig, SIGNode)


def test_parser_keeps_one_cardinality_with_string_value_hint():
    tpl = _make_in_list_template()
    lift = parse_template_to_sig(tpl, disambig_hints={"h0": "string_value"})
    hole = lift.holes[0]
    assert hole.card == Cardinality.ONE


def test_parser_unknown_hint_still_abstains():
    tpl = _make_in_list_template()
    try:
        parse_template_to_sig(tpl, disambig_hints={"h0": "totally_unrecognized"})
    except SQL0AmbiguousIntent:
        return
    raise AssertionError("expected SQL0AmbiguousIntent on unknown hint")


# --- pipeline helper --------------------------------------------------------


def test_disambig_helper_returns_provenance(monkeypatch):
    # Force the deterministic heuristic so the test is hermetic.
    monkeypatch.setenv("IR_SAM_DISAMBIG_POLICY", "heuristic")
    from core.pipeline import _try_disambiguate_sql_in

    tpl = _make_in_list_template()
    prov = _try_disambiguate_sql_in(tpl)
    assert prov["disambig_invoked"] is True
    assert prov["disambig_site"] == "sql/in_position"
    assert prov["disambig_policy"] == "HeuristicPolicy"
    assert prov["disambig_label"] in label_schema.SQL_IN_POSITION.labels
    assert "disambig_hints" in prov
    # Hints must map every hole.
    assert set(prov["disambig_hints"]) == {"h0"}


# --- corpus generator soundness --------------------------------------------


def test_corpus_synthetic_examples_have_registered_labels():
    from bench.disambig_corpus import generate_synthetic

    examples = generate_synthetic()
    assert examples, "synthetic generator must emit at least one example"
    for ex in examples:
        ls = label_schema.get(ex.interpreter, ex.site)
        assert ex.label in ls.labels, (
            f"corpus example has unregistered label {ex.label!r} "
            f"for {ex.interpreter}/{ex.site}"
        )


def test_corpus_build_writes_three_splits(tmp_path):
    from bench.disambig_corpus import build_corpus

    counts = build_corpus(tmp_path, include_real_world=False, seed=0)
    assert set(counts) == {"train", "valid", "test"}
    total = sum(counts.values())
    assert total > 0
    for name in ("train.jsonl", "valid.jsonl", "test.jsonl"):
        assert (tmp_path / name).exists()
