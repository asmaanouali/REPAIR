# IR-SAM MVP Specification (frozen)

**Scope:** Java host language, SQL interpreter, JDBC binder catalog.
**Frozen at:** end of Phase 1, month 6.
**Out of scope for MVP:** Python, JS/TS; non-JDBC frameworks (Spring,
MyBatis, Hibernate are added in Phase 4/7); CWEs other than CWE-89;
LLM-based disambiguation (Phase 4).

The MVP is the minimum system that proves the IAM model end-to-end on
**Juliet CWE-89 (Java)** and **OWASP Benchmark SQLi (Java)**. It must
hit the gates listed in §10 before Phase 2 is declared done.

---

## 1. End-to-end I/O contract

**Input.** A Maven/Gradle Java project plus a SARIF report from one or
more detectors (CodeQL, Semgrep, SonarQube). The SARIF is normalized
to a list of `IRSAMFinding` via [core/ingest](../core/ingest).

**Output.** Per finding, either:
- a unified diff `<file>.patch` applying a structurally-sound JDBC
  prepared-statement rewrite, **and** a validator report
  `<file>.report.json` showing all gates passed, **or**
- a `⊥` record `<file>.abstain.json` with a typed reason
  (`UnsupportedDialect`, `AmbiguousIntent`, `IdentifierNotInDT`,
  `NoCatalogMatch`, `BuildFailure`, `TestRegression`,
  `ResidualSAST`).

The MVP is **not** an IDE plugin; it is a CLI plus a Python library.

## 2. Stage-by-stage contracts

### Stage A — Sink Locator
**In:** project root + detector SARIF.
**Out:** `list[IRSAMFinding]`, deduplicated and CWE-89-filtered.
**Implementation:** `core.ingest.codeql.adapt`, `.semgrep.adapt`,
`.sonarqube.adapt`; `core.ingest.unified.dedup_findings`.
**Tests:** golden SARIF fixtures with expected finding counts and
hashes.

### Stage B — Slice Extractor
**In:** finding + project AST.
**Out:** **intra-procedural backward slice** from `finding.sink.arg[i]`
in SSA form. For MVP we use **Spoon** to build the AST and a
hand-written backward walker (≤ 800 LoC) that handles:
- assignments, locals, parameters,
- `String` concatenation (`+`, `String.join`, `StringBuilder.append`),
- `String.format`, `MessageFormat.format`,
- bounded `for`/`while` over a `Collection<String>` building a CSV /
  `IN`-list,
- ternary expressions, `if`/`else` branches (becomes a `branch` node
  in the string algebra),
- method calls that the slicer can inline as constant returns when
  the callee is in the same compilation unit and is a one-liner.
**Out of MVP scope:** cross-class slicing, framework-injected
dependencies, `Reflection`, `Optional` chains, lambda capture across
methods. These force stage D to abstain.

### Stage C — String-Construction Reconstructor
**In:** slice.
**Out:** a **parameterized template** `T(h_1,…,h_n)` where each `h_i`
is a hole with `(SyntCtx, SemType, Cardinality, host_expr,
proven_in_DT)`. Implementation reuses a small symbolic regex/CFG
approximator (~ JSA-style) — for MVP, expressing the slice as a
context-free grammar over `{const, var, concat, format, loop-join,
branch}` is sufficient.

### Stage D — Intent Parser (SQL)
**In:** `T` + dialect hint (default ANSI; MySQL/Postgres/H2
configurable).
**Implementation:** ANTLR4 grammar derived from the official MySQL
parser grammar, restricted to `SQL₀` (see
[soundness-proof.md](soundness-proof.md)). On parse failure, abstain
(`AmbiguousIntent`). On parse success, lift the parse tree to a
`SIGNode` per [core/iam](../core/iam) and place `Hole` nodes at the
positions of `T`'s holes.

### Stage E — Safe-API Binder φ (JDBC)
**In:** IAM.
**Implementation:** rule-driven via the [Binding DSL](binder-dsl.md)
and the catalog in [`binders/sql_jdbc.yaml`](../binders/sql_jdbc.yaml).
Each binder rule, on a successful pattern match, emits a structured
`Patch` object: a list of host-AST edits + a list of `HostRealization`
records to be re-checked by stage G.

### Stage F — Patch Synthesis
**In:** original Java AST + `Patch`.
**Implementation:** **Spoon** AST rewrites:
1. Insert `PreparedStatement` declaration above the sink, wrapped in
   `try-with-resources` (or merged with an existing one).
2. Replace the original `Statement.executeQuery(concatenated)` with
   `ps.executeQuery()`.
3. Insert `ps.setX(i, expr)` calls for each value hole, with a
   bounded loop for `IN`-list holes.
4. Insert allow-list lookups for identifier holes (the lookup table is
   generated as a `private static final Set<String>` at class scope).
5. Manage imports, throws-clauses, resource closing.
**Output:** a unified diff (no in-place writes by default).

### Stage G — Validator (5 gates)
1. **Compile gate:** project still compiles under the same build
   system (Maven/Gradle wrapper). Failure ⇒ `BuildFailure`.
2. **Regression gate:** existing test suite passes
   (`mvn test -q -fae`). Failure ⇒ `TestRegression`.
3. **Structural gate:** `core.iam.structurally_sound` on the patched
   AST returns `(True, [])`. Failure ⇒ `StructuralCheckFailed`.
4. **Re-SAST gate:** re-run CodeQL CWE-89 query; no result at the
   patched site. Failure ⇒ `ResidualSAST`.
5. **Differential gate:** for each call site, run a containerized DB
   (H2 in-process; MySQL via docker-compose for "deep" mode) with a
   grammar-driven attack-payload generator (see §3) and a
   benign-payload generator; assert that for every `(benign, attack)`
   pair, the patched program's externally observable output matches
   the pre-patch program's output on the benign payload and contains
   **no** attacker-controlled tokens for the attack payload.

## 3. Differential oracle (MVP edition)

The MVP ships a minimal grammar-driven payload generator with the
following grammars:

```
benign_string    := /[A-Za-z0-9 _.@-]{1,32}/
benign_integer   := /[0-9]{1,9}/
attack_string    := classic_sqli | quote_break | union_inject | comment_inject
classic_sqli     := "' OR 1=1 --"
quote_break      := "' " benign_string " '"
union_inject     := "' UNION SELECT NULL --"
comment_inject   := benign_string " /* ' OR 1=1 -- */"
```

For each `value`-hole the runner enumerates `benign × attack` pairs
(bounded N per site, default 32) and compares observable behavior to
the pre-patch baseline.

## 4. Configuration & CLI

```
irsam scan      --project <root> --sarif <a.sarif> [--sarif b.sarif ...]
irsam plan      --findings findings.jsonl
irsam patch     --findings findings.jsonl --out patches/
irsam validate  --project <root> --patches patches/
irsam pipeline  --project <root> --sarif <...> --out out/
```

All commands emit machine-readable artifacts to `out/` (JSON Lines)
suitable for the Phase-5 evaluation harness.

## 5. Configuration file

`irsam.yaml` at project root:

```yaml
language: java
build: maven        # or gradle
db_dialect: ansi    # ansi | mysql | postgres | h2
abstain_on:
  - dialect_mismatch
  - dynamic_orderby_with_unknown_column
binder_catalogs:
  - binders/sql_jdbc.yaml
validator:
  diff_oracle: light   # light | deep
  diff_oracle_n_pairs: 32
```

## 6. Project layout for an in-scope target

A target project is in-scope iff:
- it builds with Maven or Gradle (wrapped),
- has a non-empty `src/test/java` test suite,
- declares its DB driver explicitly (so we can pick a dialect).

Out-of-scope targets are reported as `AbstainProject`.

## 7. Performance budget

- Stage A: ≤ 1 s / 100 findings (SARIF parsing).
- Stage B–F: ≤ 5 s / finding median, ≤ 30 s p95.
- Stage G (light oracle): ≤ 30 s / finding.
- Stage G (deep oracle, dockerized DB): ≤ 5 min / finding.

## 8. Error & abstention model

All abstentions and errors are typed and emitted to the `out/`
directory; no abstention is silent. Reasons are mapped 1:1 to the
typed enum in `core/cli/errors.py` (Phase 2 deliverable).

## 9. Logging & telemetry

JSON-structured logs to stderr, one record per stage transition,
including per-stage durations. No network telemetry. No telemetry
file outside the project root.

## 10. MVP acceptance gates (Phase 2 exit criteria)

1. **Juliet CWE-89 (Java)**: ≥ 80 % patch-applicability, ≥ 95 % of
   applied patches pass all five validator gates, 0 residual CWE-89
   reported by CodeQL.
2. **OWASP Benchmark SQLi**: ≥ 80 % true-positive sink patched without
   regressing any benign test in the harness.
3. **Soundness audit**: a manual spot-check of 30 patches by the
   supervisor confirms structural-soundness reasoning.
4. **Reproducibility**: `docker compose run --rm dev make mvp-eval`
   regenerates §10.1–§10.2 numbers from raw datasets in < 6 hours on
   the reference machine (32 GB RAM, 8 cores).
5. **Code quality**: ruff clean, mypy strict clean, pytest ≥ 85 %
   line coverage of `core/`.
