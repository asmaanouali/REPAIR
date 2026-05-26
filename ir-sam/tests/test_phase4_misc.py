"""Phase-4 disambiguator, attack-generator, and oracle harness tests."""
from bench.attack_gen import payloads_for, corpus_summary
from core.disambig import HeuristicPolicy, Question, load_default_policy
from scripts.oracle_harness import (
    OracleCase, SQLiteBackend, make_client,
)


def test_attack_gen_has_sql_corpus():
    c = corpus_summary()
    assert c["sql"] >= 8
    assert c["ldap"] >= 4
    assert c["xpath"] >= 3


def test_attack_gen_payloads_typed():
    for p in payloads_for("sql"):
        assert p.interpreter == "sql"
        assert p.kind and p.payload


def test_disambig_heuristic_default():
    pol = HeuristicPolicy()
    q = Question(sig_text="SELECT * FROM t WHERE id IN (<<H0>>)",
                 context="java; host_type=java.util.List<Integer>",
                 labels=("string_value", "in_list_csv"))
    ans = pol.choose(q)
    assert ans.label == "in_list_csv"
    assert ans.source == "heuristic"


def test_disambig_default_factory_returns_policy():
    pol = load_default_policy()
    q = Question(sig_text="t", context="", labels=("a", "b"))
    a = pol.choose(q)
    assert a.label in ("a", "b")


def test_sqlite_oracle_blocks_sql_injection():
    case = OracleCase(
        interpreter="sql", fixture_id="users",
        original_template="SELECT id FROM users WHERE name = '{p}'",
        patched_template="SELECT id FROM users WHERE name = ?",
        param_kind="string",
    )
    out = SQLiteBackend().run(case)
    # patched form must neutralize every classical attack
    assert out.overall_safe
    # baseline equivalence holds
    assert out.benign_equivalent


def test_make_client_dispatch():
    assert make_client("sql").name.startswith("sqlite3")
    assert make_client("ldap").name.startswith("ldap")
    assert make_client("xpath").name.startswith("xpath")
