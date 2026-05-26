# Test-Phase Findings

This document tracks issues surfaced by the production-grade test phase
introduced in v2.x. Each entry has a stable ID, severity, current status,
and the test that pins the regression.

---

## TPF-001 — 9 of 10 binder catalogs fail the schema

**Severity:** medium (correctness)
**Status:** open
**Pinned by:** `tests/test_binder_catalogs.py` (xfail, `strict=False`)

The catalogs in `binders/` were authored with extensions the schema
forbids:

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

---
