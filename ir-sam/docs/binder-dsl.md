# Binding-Catalog DSL v0

**Status:** Phase 1 design freeze.
**Scope:** declarative description of `φ` binder rules
(see [formal-model.md](formal-model.md) §4).

The binder catalog is **data, not code**. Each binder is a YAML
document validated against
[`schemas/binder.schema.json`](../schemas/binder.schema.json) and
loaded at runtime by [`core.binder`](../core/binder/__init__.py).
This keeps the trusted core small and lets per-(interpreter, framework)
catalogs be reviewed and audited independently.

---

## 1. Design goals

1. **Auditable.** A security reviewer must be able to read a binder
   YAML and decide whether the rewrite satisfies the §5 sufficient
   structural condition *without reading host-language AST APIs*.
2. **Closed by construction.** It must be impossible to express a
   binder that emits attacker-controlled bytes outside a
   parameterizing API or allow-list lookup. The DSL syntax simply
   does not provide such a primitive.
3. **Composable.** Binders match sub-graphs of the SIG; the matcher
   composes rule outputs greedily, deterministically, with no
   left-over holes.
4. **Versioned.** Every binder file carries `dsl_version` and `binder_version`;
   loaders reject unknown versions.
5. **Framework-aware.** A binder declares
   `applies_to.{interpreter, host_language, framework}` and is only
   considered when these match the host project's declared
   configuration (`irsam.yaml`).

## 2. Top-level schema

```yaml
dsl_version: "0"          # bumped on breaking changes
catalog:
  id: "sql-jdbc"          # globally unique
  version: "0.1.0"
  applies_to:
    interpreter: sql
    host_language: java
    framework: jdbc
  parameterizing_apis:    # trusted set; consumed by stage G
    - "java.sql.PreparedStatement.setString"
    - "java.sql.PreparedStatement.setInt"
    - "java.sql.PreparedStatement.setLong"
    - "java.sql.PreparedStatement.setBigDecimal"
    - "java.sql.PreparedStatement.setBoolean"
    - "java.sql.PreparedStatement.setDate"
    - "java.sql.PreparedStatement.setTimestamp"
    - "java.sql.PreparedStatement.setObject"
  binders:
    - id: ...
      pattern: ...
      rewrite: ...
      preconditions: [ ... ]
      postconditions: [ ... ]
      proof_obligation: ...
```

## 3. Binder rule

A binder is the 5-tuple `(Pattern, Rewrite, Pre, Post, Proof)`:

```yaml
- id: sql-eq-value
  pattern:                # a SIG subgraph schema
    kind: Comparison
    children:
      - kind: Column
        bind: col
      - lit: "="
      - kind: Hole
        ctx: value
        sem_in: [string, integer, decimal, boolean, date]
        bind: v
  rewrite:                # host AST edit list
    template_string: "{col} = ?"
    bindings:
      - param_index: $auto
        host_expr: "$v.host_expr"
        api: |
          {{ choose_setter($v.sem) }}     # macro: setString / setInt / ...
  preconditions:
    - host_has_connection_in_scope
    - jdbc_imports_available_or_addable
  postconditions:
    - resource_managed_try_with_resources
    - structural_value_via_parameterized_api: $v
  proof_obligation: "Lemma 1 (Parameter inertness)."
```

`pattern` is a tree pattern with named binds (`$col`, `$v`). The
matcher uses subtree matching with hole-variance: a `Hole` node in a
pattern matches any `Hole` node in the SIG with a compatible
`(ctx, sem_in, card)`.

`rewrite.template_string` is the **SQL** fragment to splice into the
prepared-statement template — it may only contain `?` markers and
literal identifiers obtained from `$col`/`$table` binds that resolve
through `Σ` to `D_T` constants.

`rewrite.bindings` is the host-AST edit list. The `api` field is
**restricted** to elements of `catalog.parameterizing_apis`. The DSL
loader rejects binders that name an API not in that set; this is the
mechanical realization of design goal 2.

`postconditions` are checks the binder asserts; stage G re-verifies
each one structurally.

## 4. Identifier-hole binders

```yaml
- id: sql-orderby-ident
  pattern:
    kind: OrderList
    children:
      - kind: Hole
        ctx: identifier
        sem_in: [enum]
        bind: c
  rewrite:
    template_string: "{c} {dir}"
    bindings:
      - kind: allowlist_lookup
        bind_target: c
        allowlist_source: "$c.allowlist"   # provided by Σ
        on_miss: throw_IllegalArgumentException
  preconditions:
    - hole_allowlist_nonempty: $c
  postconditions:
    - structural_identifier_via_allowlist: $c
  proof_obligation: "Lemma 2 (Identifier allow-list closure)."
```

The DSL provides exactly two "binding kinds": `parameterized-api`
(value holes) and `allowlist_lookup` (identifier holes). There is no
escape hatch.

## 5. `IN (?, ?, …)` binders

```yaml
- id: sql-in-list
  pattern:
    kind: InExpr
    children:
      - kind: Column
        bind: col
      - kind: Hole
        ctx: value
        card: many.bounded
        bind: vs
  rewrite:
    template_string: "{col} IN ({placeholders($vs)})"
    bindings:
      - param_index: $auto
        host_expr: "$vs.host_expr_iter"      # macro: foreach binding
        api: |
          {{ choose_setter($vs.sem) }}
  preconditions:
    - hole_cardinality_bounded: $vs
    - bound_max_le: { hole: $vs, max: 1024 }
  postconditions:
    - structural_value_via_parameterized_api: $vs
```

`many.unbounded` holes are rejected by the DSL (they would require
runtime-variable SQL templates, which falls outside `SQL₀`).

## 6. Macro language

The DSL provides a tiny macro language used inside `template_string`
and `api` fields:

- `placeholders($v)` — emits `?, ?, …, ?` for the bound cardinality.
- `choose_setter($v.sem)` — maps `SemType` to a setter from
  `parameterizing_apis`.
- `iter($v)` — generates the host-AST loop binding each element.

Macros are pure; they take only DSL-bound names as input.

## 7. Loader & validation

The loader (`core.binder.loader.load_catalog`) performs:

1. JSON-Schema validation against
   [`schemas/binder.schema.json`](../schemas/binder.schema.json).
2. **Closure check.** Every `api:` in a binder must be a member of
   `catalog.parameterizing_apis`. **Reject otherwise.**
3. **Hole-kind check.** Every `bindings.kind` is one of
   `parameterized-api` or `allowlist_lookup`.
4. **Pattern well-formedness.** Pattern nodes reference only known
   SIG node kinds.
5. **Proof-obligation listed.** Required string field; reviewers
   read this when auditing.

A binder catalog passing the loader is the formal object referred to
as `φ` for that (interpreter, host, framework) triple.

## 8. Versioning policy

- `dsl_version` major bump on any breaking change to the loader.
- `catalog.version` SemVer.
- Catalogs commit to backward compatibility within a major DSL
  version; new binders may be added without bumping `dsl_version`.

## 9. Out-of-DSL bindings (Phase 4+)

Some rewrites that emerge in Phase 4 (e.g., framework-aware
JdbcTemplate refactors, Django ORM Q-object construction) may need
side-effects not expressible in this DSL. These are introduced via a
**plugin** API (`core.binder.plugins`) which carries its own audit
checklist and is NOT enabled in the MVP catalog.
