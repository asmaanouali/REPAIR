# Test-Phase Findings

This document tracks issues surfaced by the production-grade test phase
introduced in v2.x. Each entry has a stable ID, severity, current status,
and the test that pins the regression.

---

## TPF-001 — 9 of 10 binder catalogs fail the schema

**Severity:** medium (correctness)
**Status:** resolved (v2.x)
**Pinned by:** `tests/test_binder_catalogs.py::test_catalog_validates_against_json_schema`

The catalogs in `binders/` were originally authored with extensions the
schema forbade:

| Catalog                       | Failure mode                                            |
| ----------------------------- | ------------------------------------------------------- |
| `ldap.yaml`, `xpath.yaml`     | `host_language: any` not in schema enum                 |
| `django_orm.yaml`             | binders carry `doc:` field — `additionalProperties=false` rejects |
| `hibernate_hql.yaml`          | pattern/rewrite fields not in schema                    |
| `jpa.yaml`                    | pattern/rewrite fields not in schema                    |
| `mybatis.yaml`                | pattern/rewrite fields not in schema                    |
| `spring_jdbctemplate.yaml`    | pattern/rewrite fields not in schema                    |
| `sql_jsts.yaml`               | pattern/rewrite fields not in schema                    |
| `sql_pydbapi.yaml`            | pattern/rewrite fields not in schema                    |

Only `sql_jdbc.yaml` validates cleanly.

**Resolution path:**

1. Decide whether each non-validating field is intentional and extend
   `schemas/binder.schema.json` (and bump `dsl_version`), or
2. Treat the field as accidental and strip it from the YAML.

When fixed, the corresponding entry in `_KNOWN_BROKEN` inside
`tests/test_binder_catalogs.py` must be removed; the xfail will become
an XPASS otherwise (`strict=False` lets the run stay green but signals
the drift in the report).

**Resolution (taken).** Option 1 was applied: the schema was extended to
admit the fields the catalogs legitimately use — the per-binder `doc`
annotation, `host_language: "any"` (for interpreter-only catalogs such
as LDAP and XPath that bind in both Java and Python), and the full
`pattern`/`rewrite` vocabulary (`Comparison`, `LikeExpr`, `InExpr`,
`Column`, `Token`, `Hole` nodes and the
`parameterize`/`replace_sink`/`insert_guard` rewrite kinds). All eleven
catalogs now validate. `load_catalog` calls `jsonschema.validate` on
every load, and the parametrized test
`test_catalog_validates_against_json_schema` asserts zero schema
violations for each YAML in `binders/`, so a regression fails CI
immediately. `scripts/validate_catalogs.py` runs the same check as a
standalone command. Verified: `45 passed`.

---
