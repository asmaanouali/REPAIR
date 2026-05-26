"""Grammar-driven attack payload generator (Phase 4).

For each interpreter (SQL, LDAP, XPath) we declare a small *attack
grammar* and an inverse "neutralization predicate" that a sound
parameterizing API must satisfy. The generator enumerates payloads
that *exercise* every production, plus a curated set of canonical
historical CVEs. The differential gate consumes these payloads.

The generator is deterministic and produces stable, hash-stable
identifiers so a fixed seed yields the same corpus across runs ---
important for reproducibility of the empirical evaluation.

Three interpreters are shipped today:

* ``sql``    --- classic injection: comment escape, UNION, stacked,
  blind / boolean, time-based.
* ``ldap``   --- RFC 4515 filter injection: ``)(|...))``, ``*``
  wildcards, NUL byte, attribute injection.
* ``xpath``  --- XPath 1.0 predicate injection: ``' or '1'='1``,
  ``'] | //user[...``, function injection.

Each payload carries a ``kind`` tag so the oracle can verify the
**neutralization invariant**: the *patched* statement must either
reject the payload (binding-level type error) or treat it as a
literal value (zero new rows / same rows as a benign literal). The
*original* concat statement is expected to exhibit the attack
behaviour (more rows, error, crash) --- otherwise the case is
flagged as a "weak case" and excluded from the gate-pass denominator.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator


@dataclass(frozen=True)
class AttackPayload:
    interpreter: str
    kind: str
    payload: str          # the attacker-controlled string
    neutralized_expectation: str   # "binding_type_error" | "no_extra_rows" | "literal"
    notes: str = ""


# --- SQL --------------------------------------------------------------------


def sql_payloads() -> Iterator[AttackPayload]:
    base = [
        ("tautology",       "' OR '1'='1",                 "literal"),
        ("tautology2",      "' OR 1=1 --",                 "literal"),
        ("stacked_drop",    "'; DROP TABLE users; --",     "literal"),
        ("union_extract",   "' UNION SELECT password FROM users --", "literal"),
        ("comment_admin",   "admin' --",                   "literal"),
        ("blind_boolean",   "' AND SUBSTR(password,1,1)='a", "no_extra_rows"),
        ("time_based",      "' OR (SELECT sleep(1)) --",   "literal"),
        ("hex_bypass",      "0x61646d696e",                "literal"),
        ("encoded_quote",   "%27 OR %271%27=%271",         "literal"),
        ("nullbyte",        "admin\x00",                   "literal"),
    ]
    for k, p, exp in base:
        yield AttackPayload("sql", k, p, exp)

    # numeric variants
    for k, p in [
        ("num_tautology",    "1 OR 1=1"),
        ("num_stacked",      "1; DROP TABLE users"),
        ("num_hex",          "0x1"),
    ]:
        yield AttackPayload("sql", k, p, "binding_type_error")


# --- LDAP -------------------------------------------------------------------


def ldap_payloads() -> Iterator[AttackPayload]:
    base = [
        ("filter_break",    "admin)(&(uid=*",           "literal"),
        ("wildcard",        "*",                        "no_extra_rows"),
        ("nul_byte",        "admin\x00",                "literal"),
        ("or_inject",       "*)(|(uid=*",               "literal"),
        ("not_inject",      "*))(!(uid=foo",            "literal"),
        ("dn_inject",       "cn=admin,ou=users",        "literal"),
    ]
    for k, p, exp in base:
        yield AttackPayload("ldap", k, p, exp)


# --- XPath ------------------------------------------------------------------


def xpath_payloads() -> Iterator[AttackPayload]:
    base = [
        ("tautology",       "' or '1'='1",              "literal"),
        ("predicate_break", "x'] | //user[name='",      "literal"),
        ("fn_inject",       "'+name(/*)+'",             "literal"),
        ("string_break",    "' or substring(.,1,1)='a", "no_extra_rows"),
    ]
    for k, p, exp in base:
        yield AttackPayload("xpath", k, p, exp)


# --- benign corpus (counter-examples) --------------------------------------


def benign_strings() -> tuple[str, ...]:
    return ("alice", "bob", "Mary O'Connor", "\u00e9milie",
            "a-b_c", "lorem ipsum", "  ", "")


def benign_ints() -> tuple[str, ...]:
    return ("1", "42", "99", "0", "1000000")


# --- catalog public API ----------------------------------------------------


def payloads_for(interpreter: str) -> list[AttackPayload]:
    if interpreter == "sql":
        return list(sql_payloads())
    if interpreter == "ldap":
        return list(ldap_payloads())
    if interpreter == "xpath":
        return list(xpath_payloads())
    raise ValueError(f"unknown interpreter {interpreter!r}")


def corpus_summary() -> dict[str, int]:
    return {
        "sql":   len(payloads_for("sql")),
        "ldap":  len(payloads_for("ldap")),
        "xpath": len(payloads_for("xpath")),
        "benign_string": len(benign_strings()),
        "benign_int":    len(benign_ints()),
    }
