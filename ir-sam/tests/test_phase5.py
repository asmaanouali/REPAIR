"""Phase-5 tests: corpus, metrics, baselines, study, end-to-end."""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from bench.eval_corpus import EvalCase, corpus_stats, load_evaluable_subset
from baselines import (ALL_BASELINES, BaselineResult,
                       IrSamBaseline, SemgrepAutofixBaseline,
                       VulRepairBaseline, SeqTransBaseline,
                       ChatRepairBaseline, LlmZeroShotBaseline,
                       CodeqlGpt4Baseline)
from eval.metrics import (CaseObservation, benign_equivalent_text,
                          residual_cwe_count, six_metrics, token_jaccard)
from eval.failure_modes import build_catalog, classify, write_catalog
from study.randomization import assign, write_csv
from study.analysis import friedman, holm_bonferroni, krippendorff_alpha_ordinal


# --- corpus -----------------------------------------------------------


def test_corpus_synth_loads_and_is_in_scope(tmp_path):
    cases = load_evaluable_subset(datasets=("synth",), synth_work=tmp_path)
    assert len(cases) >= 16
    for c in cases:
        assert c.interpreter in ("sql", "ldap", "xpath")
        assert c.language in ("java", "python")
        assert c.pre_path.exists() and c.post_path is not None
        assert c.post_path.exists()
    stats = corpus_stats(cases)
    assert stats["total"] == len(cases)
    assert set(stats["by_cwe"]).issubset(
        {"CWE-89", "CWE-90", "CWE-91", "CWE-643", "CWE-78", "CWE-94"})


# --- metrics ----------------------------------------------------------


def _obs(**kw) -> CaseObservation:
    base = dict(case_id="c", tool="t", applied=True, functional_pass=True,
                benign_equivalent=True, residual_cwe_count=0,
                latency_seconds=0.01, abstained=False,
                ground_truth_irreparable=False, notes="")
    base.update(kw)
    return CaseObservation(**base)


def test_metrics_empty_observations():
    m = six_metrics([])
    assert m["M1_patch_applicability"] == 0.0
    assert m["M2_functional_fix_rate"] == 0.0
    assert m["M6_abstention_precision"] == 1.0


def test_metrics_all_apply_and_pass():
    obs = [_obs(case_id=f"c{i}") for i in range(5)]
    m = six_metrics(obs)
    assert m["M1_patch_applicability"] == 1.0
    assert m["M2_functional_fix_rate"] == 1.0
    assert m["M3_semantic_equivalence"] == 1.0
    assert m["M4_residual_cwe_mean"] == 0.0


def test_metrics_all_abstain():
    obs = [_obs(case_id=f"c{i}", applied=False, functional_pass=False,
                benign_equivalent=False, abstained=True) for i in range(4)]
    m = six_metrics(obs)
    assert m["M1_patch_applicability"] == 0.0
    assert m["M2_functional_fix_rate"] == 0.0
    assert m["M3_semantic_equivalence"] == 0.0
    assert m["M6_abstention_precision"] == 0.0


def test_metrics_abstention_precision_partial():
    obs = [
        _obs(applied=False, functional_pass=False, abstained=True,
             ground_truth_irreparable=True),
        _obs(applied=False, functional_pass=False, abstained=True,
             ground_truth_irreparable=False),
    ]
    assert six_metrics(obs)["M6_abstention_precision"] == 0.5


def test_residual_cwe_counts_python_concat():
    src = 'cur.execute("SELECT * WHERE id=" + uid)'
    assert residual_cwe_count(src, "python") == 1


def test_residual_cwe_counts_java_concat():
    src = 'st.executeQuery("SELECT id FROM u WHERE n=\'" + name + "\'")'
    assert residual_cwe_count(src, "java") == 1


def test_token_jaccard_identity():
    assert token_jaccard("a b c", "a b c") == 1.0
    assert token_jaccard("", "") == 1.0
    assert benign_equivalent_text("execute(?, (x,))", "execute(?, (x,))")


# --- baselines --------------------------------------------------------


@pytest.fixture(scope="module")
def synth_cases(tmp_path_factory):
    work = tmp_path_factory.mktemp("synth")
    return load_evaluable_subset(datasets=("synth",), synth_work=work)


@pytest.mark.parametrize("BL", [
    SemgrepAutofixBaseline, VulRepairBaseline, SeqTransBaseline,
    ChatRepairBaseline, LlmZeroShotBaseline, CodeqlGpt4Baseline,
])
def test_baseline_returns_result_shape(BL, synth_cases):
    bl = BL()
    res = bl.run(synth_cases[0])
    assert isinstance(res, BaselineResult)
    assert res.tier in ("real", "synthetic")
    assert isinstance(res.applied, bool)
    assert isinstance(res.abstained, bool)


def test_baselines_deterministic_per_seed(synth_cases):
    bl_a = VulRepairBaseline()
    bl_b = VulRepairBaseline()
    r_a = [bl_a.run(c).applied for c in synth_cases]
    r_b = [bl_b.run(c).applied for c in synth_cases]
    assert r_a == r_b


def test_irsam_baseline_runs(synth_cases):
    bl = IrSamBaseline()
    # filter to non-java to avoid the heavyweight java pipeline import path
    cases = [c for c in synth_cases if c.language != "java"][:3]
    assert cases
    for c in cases:
        res = bl.run(c)
        assert isinstance(res, BaselineResult)
        assert res.tier == "real"


# --- failure modes ----------------------------------------------------


def test_failure_classify_known_labels():
    assert classify("parse:SQL0AmbiguousIntent: ...") == "sql0_ambiguous_intent"
    assert classify("recon:non_string_concat") == "non_string_concat"
    assert classify("slice:escapes_method") == "escapes_method"
    assert classify("model hallucinated non-existent API") == "llm_hallucinated_api"
    assert classify("") == "uncategorized"


def test_build_catalog_top_k(tmp_path):
    recs = []
    for i in range(8):
        recs.append({"tool": "T", "case_id": f"c{i}",
                     "notes": "parse:SQL0AmbiguousIntent: x",
                     "applied": False, "functional_pass": False})
    for i in range(3):
        recs.append({"tool": "T", "case_id": f"d{i}",
                     "notes": "recon:non_string_concat",
                     "applied": False, "functional_pass": False})
    recs.append({"tool": "T", "case_id": "ok",
                 "notes": "", "applied": True, "functional_pass": True})
    catalog = build_catalog(recs, top_k=10)
    assert catalog[0].label == "sql0_ambiguous_intent"
    assert catalog[0].count == 8
    write_catalog(catalog, tmp_path)
    assert (tmp_path / "phase5_failure_modes.json").exists()
    assert (tmp_path / "phase5_failure_modes.md").exists()


# --- study ------------------------------------------------------------


def test_randomization_is_deterministic_and_balanced(tmp_path):
    reviewers = [f"R{i:02d}" for i in range(20)]
    cases = [f"case-{i}" for i in range(12)]
    a1 = assign(reviewers, cases, n_triplets=6, study_secret="S1")
    a2 = assign(reviewers, cases, n_triplets=6, study_secret="S1")
    assert a1 == a2
    # IR-SAM appears in every triplet
    for asg in a1:
        assert "IR-SAM" in (asg.cond_A, asg.cond_B, asg.cond_C)
    write_csv(a1, tmp_path / "assignments.csv")
    rows = list(csv.DictReader((tmp_path / "assignments.csv").open()))
    assert len(rows) == len(a1)


def test_randomization_different_secret_changes_assignment():
    reviewers = ["A", "B"]
    cases = [f"c-{i}" for i in range(8)]
    a1 = assign(reviewers, cases, n_triplets=4, study_secret="X")
    a2 = assign(reviewers, cases, n_triplets=4, study_secret="Y")
    assert a1 != a2


def test_friedman_basic():
    # Three condition columns, IR-SAM clearly best
    blocks = [[5, 3, 2], [4, 3, 2], [5, 4, 3], [5, 3, 1], [4, 2, 2]]
    chi2, p = friedman(blocks)
    assert chi2 > 0
    assert 0.0 <= p <= 1.0


def test_holm_bonferroni_monotone():
    adj = holm_bonferroni([0.01, 0.02, 0.04])
    assert adj[0] <= adj[1] <= adj[2]
    assert all(0.0 <= x <= 1.0 for x in adj)


def test_krippendorff_perfect_agreement():
    units = [[5, 5, 5], [4, 4, 4], [3, 3, 3]]
    a = krippendorff_alpha_ordinal(units)
    assert a == 1.0


# --- end-to-end orchestrator -----------------------------------------


def test_eval_phase5_synth_end_to_end(tmp_path):
    from scripts.eval_phase5 import run_eval
    res, records = run_eval(("synth",), tmp_path)
    assert "metrics_by_tool" in res
    assert "IR-SAM" in res["metrics_by_tool"]
    # synth corpus is small but deterministic; just sanity-check it runs
    assert len(records) > 0
    assert (tmp_path / "phase5_metrics.json").exists()
    assert (tmp_path / "phase5_summary.txt").exists()
    assert (tmp_path / "phase5_observations.csv").exists()
    assert (tmp_path / "phase5_failure_modes.md").exists()
