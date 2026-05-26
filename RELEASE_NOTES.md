# IR-SAM v2.0

Framework-aware extension of IR-SAM. Bundles Phase 7: five new binder
catalogs covering the most common Java and Python web-framework SQL
APIs, a framework dispatcher (Stage A.5), and the TSE/TOSEM journal
extension manuscript.

## New since v1.0

* `ir-sam/binders/spring_jdbctemplate.yaml`  -- Spring JdbcTemplate +
  NamedParameterJdbcTemplate (positional `?` and named `:p_n`).
* `ir-sam/binders/mybatis.yaml`              -- `${var}` -> `#{var}`
  rewrite, plus concat-WHERE rewrite using `@Param`.
* `ir-sam/binders/hibernate_hql.yaml`        -- HQL `Session.createQuery`
  + `Query.setParameter("p_n", v)`.
* `ir-sam/binders/jpa.yaml`                  -- JPA / JPQL named and
  positional, jakarta + javax variants.
* `ir-sam/binders/django_orm.yaml`           -- `.extra(where=...)`,
  `.raw(...)`, cursor.execute concat -> ORM-native `.filter` or
  DB-API `params=[...]`.
* `ir-sam/core/framework/__init__.py`        -- dispatcher (Stage A.5)
  with priority-ordered signal table.
* `ir-sam/tests/test_framework_bindings.py`  -- 16 new tests.
* `paper2/main.tex` + `paper2/refs.bib`      -- TSE/TOSEM extension.

## Headline numbers

* 108 / 108 unit tests pass.
* Conference six-metric table unchanged (no regression).
* Framework dispatch covers 5 frameworks across Java + Python.

## Submission targets (extension paper)

| venue   | role     |
|---------|----------|
| TSE     | primary  |
| TOSEM   | backup   |
| EMSE    | backup-2 |

## License

MIT (code) + CC-BY-4.0 (paper, study materials).
