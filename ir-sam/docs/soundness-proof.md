# Soundness Proof for IR-SAM on the SQL + JDBC Fragment

**Status:** pen-and-paper proof + Phase 10 Lean 4 mechanization in
progress. See [reports/phase10_lean_report.md](../reports/phase10_lean_report.md)
for the current theorem inventory and proof status.

## Lean 4 mechanization cross-reference

| Pen-and-paper §        | Lean theorem (in `formal/IRSAM/`)                                   | Status   |
| ---------------------- | ------------------------------------------------------------------- | -------- |
| §3 Lemma 1 (Param. Inertness, JDBC) | `IRSAM.Soundness.SQL.jdbc_parameter_inertness`         | partial  |
| §3 Lemma 1 (IN-list)   | `IRSAM.Soundness.SQL.jdbc_in_list_induction`                        | partial  |
| §3 Lemma 1 (DB-API)    | `IRSAM.Soundness.SQL.dbapi_parameter_inertness`                     | partial  |
| §4 Lemma 2 (Identifier Allow-list Closure) | `IRSAM.Soundness.identifier_allowlist_closure`  | **closed** |
| §5 Lemma 3 (Structural Cover) | `IRSAM.Soundness.structural_cover`                           | **closed** |
| §6 Audit Soundness     | `IRSAM.Soundness.Audit.audit_sound` / `audit_complete`              | **closed** |
| §7 Main Theorem (parameterize) | `IRSAM.Soundness.Theorem.soundness_parameterize`            | **closed** |
| Phase 9A Shell (argv inertness) | `IRSAM.Soundness.Shell.argv_inertness`                     | **closed** |
| Phase 9A Java ProcessBuilder | `IRSAM.Soundness.Shell.processbuilder_inertness`              | **closed** |
| Phase 9A child_process | `IRSAM.Soundness.Shell.execfile_inertness`                          | **closed** |
| Phase 9E Path (insert_guard) | `IRSAM.Soundness.Theorem.soundness_insert_guard`              | **closed** |

The full proof obligations and the Phase 10 acceptance gate live at
[scripts/check_no_sorry.sh](../scripts/check_no_sorry.sh).

## 1. Fragment

We restrict the SIG grammar of [formal-model.md](formal-model.md#31-sig-schema-for-sql-excerpt)
to a fragment we denote **SQL₀**:

```
Query    ::= SELECT Projection FROM TableRef
             [WHERE Predicate] [ORDER_BY OrderList]
             [LIMIT Lit] [OFFSET Lit]
TableRef ::= ident(table)        (* must be in Σ allow-list *)
Projection ::= STAR | Column (',' Column)*
Column   ::= ident(column)       (* must be in Σ allow-list *)
Predicate::= Atom (AND Atom)*
Atom     ::= Column '=' Value
           | Column 'IN' '(' Value (',' Value)* ')'
           | Column 'LIKE' Value
OrderList::= ident(column) [ASC|DESC] (* must be in Σ allow-list *)
Value    ::= <HOLE: value, T, card>
Lit      ::= int | <HOLE: value, integer, one>
```

The host language is **Java**, and the binder catalog `φ` is the JDBC
catalog `B_JDBC` defined in [binder-dsl.md](binder-dsl.md). `B_JDBC`
contains exactly one rule per concrete `Atom` shape (`=`, `IN`,
`LIKE`), one rule each for `LIMIT`/`OFFSET`, and one rule for
ORDER-BY/TABLE/COLUMN identifier holes.

The interpreter `I_SQL` is the union of the ANSI SQL parser and the
parser of one supported dialect (MySQL 8, PostgreSQL 16, or H2 2.2).
We require dialects to satisfy:

**Assumption (Dialect-PS):** for the JDBC drivers shipped with the
supported dialects, parameter markers `?` are bound at the **wire
protocol** layer; the dialect's SQL **lexer** never observes the
substituted value (i.e., parameter values are not subject to lexical
re-interpretation, query-string re-parsing, or "multi-statement"
trailing parses).

This assumption is documented and externally checkable by inspecting
the wire protocol (MySQL `COM_STMT_EXECUTE`, PostgreSQL extended
query protocol "Bind" message). Empirical tests with crafted payloads
are part of the Phase 2 validator regression suite.

## 2. Lemmas

### Lemma 1 (Parameter inertness)
For any JDBC `PreparedStatement` `ps` prepared from a template
`q ∈ L_{SQL₀}` whose only attacker-influenced expressions are bound
via `ps.setX(i, v)` for value-position holes, the resulting query
executed against an Assumption-(Dialect-PS)-conforming driver is
*lexically identical* to `q` modulo `?` substitution at parse time.
That is, `v` is **never** lexed as SQL syntax tokens.

*Proof sketch.* Direct consequence of Assumption (Dialect-PS) and the
JDBC spec (JSR-221) §13.2.1: `setX` transmits `v` as a typed protocol
parameter; the server-side prepared-statement plan is fixed at
`prepareStatement` time. ∎

### Lemma 2 (Identifier allow-list closure)
For any `identifier`-position hole in `SQL₀`, `B_JDBC` rewrites the
host expression to:

```java
String safeIdent = ALLOWLIST.lookup(userExpr);  // throws on miss
// safeIdent ∈ Σ-defined finite set of constant strings ⊂ D_T
```

so the value reaching the SQL string concatenation is a member of a
finite, developer-defined set `S ⊂ D_T`.

*Proof sketch.* By construction of the identifier binder. The Phase-G
validator structurally checks that every identifier-hole site in the
patched AST contains a call to the allow-list lookup and a
`throw`/abstention on miss. ∎

### Lemma 3 (Structural cover)
Every accepted patch `p = φ(A)` for `A` parsed under SQL₀ satisfies:
for every leaf `ℓ` of the SIG `G` of `A`,

- if `ℓ` is a `value` hole, the corresponding host AST position is the
  argument of a `PreparedStatement.set*` invocation (possibly inside
  a fixed-size loop generating an `IN`-list);
- if `ℓ` is an `identifier` hole, the corresponding host AST position
  is the result of an allow-list lookup as in Lemma 2;
- if `ℓ` is a literal, it appears verbatim inside the prepared SQL
  template string.

*Proof sketch.* By induction on the SIG grammar of `SQL₀`. The base
cases are the three Atom shapes and the identifier-hole rule; the
inductive steps are conjunction (`AND`), list flattening (`IN`), and
optional clauses. Each binder in `B_JDBC` is constructed to produce
exactly these host AST shapes, and the stage-F synthesizer composes
binder outputs without altering them. ∎

## 3. Theorem

**Theorem (Soundness of `B_JDBC` on `SQL₀`).** Let `A` be an IAM
produced by stages A–D for a sink call site `f(...,e,...) ∈
Sinks_H,SQL`, where `f` is one of `Statement.execute*`,
`Connection.prepareStatement` (mis-use), or any JDBC sink in scope,
and where the SIG `G(A)` parses under `SQL₀`. Suppose
`p = φ_{B_JDBC}(A) \neq \bot`. Then for any host-program state `σ`
and any assignment of `value` holes to values in `D_T ∪ D_A`:

$$
\llbracket P_{SQL}(\exec(p, \sigma)) \rrbracket_{I_{SQL}}(\sigma)
  \;\in\; \mathrm{Intent}(A) \;\subseteq\; L_{SQL} \setminus
  \mathrm{Mal}_{SQL}.
$$

**Proof.**

(1) **Surface-string shape.** By Lemma 3, the patched host program
executes a JDBC prepared statement whose template string `T` is a
concrete instance of the SIG `G(A)` in which every value hole is a
`?` token and every identifier hole has been substituted with an
element of `D_T` (Lemma 2). Therefore `T ∈ L_{SQL₀} ⊆ L_{SQL}` and
`P_{SQL}(T)` is well-formed and has the same shape as `G(A)`.

(2) **Attacker bytes are protocol-bound.** By Lemma 1, every value
substituted by `setX` is delivered to the server as a typed protocol
parameter and is not lexed by the server's SQL parser. In particular,
no attacker-controlled byte can introduce new SQL tokens, change the
parse tree shape, or alter the prepared plan.

(3) **No identifier injection.** By Lemma 2, every identifier-hole
substitution is constrained to a finite developer-defined set of
constant strings. Hence no attacker-controlled byte can become a
table name, column name, or ORDER-BY identifier in the final query.

(4) **Intent preservation.** Combining (1)–(3), the executed query
parses to a CST that is the SIG `G(A)` with value holes replaced by
typed protocol parameters and identifier holes replaced by `D_T`
elements. By definition of `Intent(A)`, this CST belongs to
`Intent(A)`, which by construction excludes `Mal_{SQL}`.

(5) **No interpreter-state side-effects outside Intent.** Because the
prepared statement is the only `Sinks_H,SQL`-invoking expression in
the rewritten call site (stage F removes the original
`executeQuery(stringConcat)`), no other state mutation through
`I_{SQL}` is possible from this site.

(1)–(5) give the conclusion. ∎

## 4. Failure modes the theorem does **not** cover

The theorem is a statement about the SQL₀ fragment and the
`B_JDBC` catalog. It does **not** claim:

- soundness for `EXEC sp_executesql @stmt = ...` (T-SQL dynamic SQL),
- soundness in the presence of stored procedures that themselves
  build dynamic SQL on the server side,
- soundness when the application bypasses JDBC and uses a custom
  protocol layer,
- soundness for SQL features outside `SQL₀` (CTEs with dynamic
  columns, dynamic `GROUP BY`, etc.) — these require either
  extending `SQL₀` (and re-proving the lemmas) or returning `⊥`.

In each of these cases, the binder catalog is *required* by §7 of
the formal model to return `⊥`.

## 5. Mechanization plan (deferred)

A Lean 4 mechanization would:

1. Encode `L_{SQL₀}` as an inductive type indexed by hole signatures.
2. Encode `Intent(A)` as a predicate on parse trees.
3. Define `setX`-style substitution and prove a `Parametric-Subst`
   lemma corresponding to Lemma 1.
4. Define the allow-list lookup as a total function with `Option`
   return; failure to find means `⊥`.
5. Prove the theorem by structural induction on `G(A)`.

Estimated effort: 3–4 person-months. Not on the critical path for
the thesis; revisit only if reviewers explicitly require formal
mechanization.
