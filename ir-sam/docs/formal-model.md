# Formal Model of IR-SAM (Phase 1 — paper-grade)

**Document version:** 1.0 (Phase 1 freeze, month 6).
**Audience:** PhD thesis chapter 4; ICSE/FSE/USENIX program-committee
reviewers. This document is the **single source of truth** for the
mathematical objects manipulated by IR-SAM.

---

## 1. Notation

We fix a host programming language `H` (e.g., Java, Python, JS) and an
**interpreter** `I = (L_I, ⟦·⟧_I, P_I)`, where:

- `L_I ⊆ Σ_I*` is the **surface string language** of the interpreter
  — i.e., the set of well-formed strings the interpreter accepts as
  input (SQL queries, shell command lines, HTML fragments, LDAP
  filters, XPath expressions, etc.).
- `⟦·⟧_I : L_I × State → State'` is the operational semantics of the
  interpreter; `State` and `State'` model database tuples, OS process
  state, the DOM, the directory service, etc.
- `P_I : Σ_I* → L_I ⊎ {parse_error}` is the parser. `P_I` defines a
  concrete syntax tree (CST) for accepted strings.

We additionally fix:

- **Trust domain** `D_T`: the set of host-program values that are
  developer-supplied constants (string literals, configuration values,
  known-safe identifiers from a finite allow-list).
- **Attack domain** `D_A`: the set of host-program values that an
  adversary can influence (HTTP parameters, headers, file contents,
  RPC payloads, …). We assume `D_T ∩ D_A = ∅` modulo conservative
  taint analysis.
- A finite set of **sink APIs** `Sinks_H,I ⊆ API(H)` whose effect is
  to invoke `⟦·⟧_I` on a string argument. For each sink API
  `s ∈ Sinks_H,I` and argument position `i`, write `s.arg[i]` for the
  formal parameter.

## 2. Vulnerability

Let `e` be an expression of `H` evaluating to `(s, σ) ∈ Σ_I* × State`
and let `f ∈ Sinks_H,I` with tainted parameter index `i`. The
program-point `f(...,e,...)` is **vulnerable** w.r.t. a malicious
behavior set `Mal_I ⊆ State'` iff:

> ∃ a `D_A`-controlled assignment to the free variables of `e` such
> that `P_I(s) ∈ L_I` and `⟦P_I(s)⟧_I(σ) ∈ Mal_I`.

In words: an attacker can choose untrusted inputs so that the resulting
surface string is interpreted in a way that produces malicious
behavior. `Mal_I` is fixed per interpreter (e.g., for SQL: any query
shape not in the developer's intent set; for shell: any command not
in the intent set; for HTML/DOM: any subtree containing executable
script under the document's effective origin).

## 3. Intent Abstract Model (IAM)

The **IAM** of a vulnerable call site is the 4-tuple

$$
A = (G, H, C, \Sigma)
$$

where:

- **G — Semantic Intent Graph (SIG).** A typed AST conforming to a
  schema `S_I` over the interpreter's grammar, with **HOLE** nodes.
  Formally, `G ∈ T(S_I, V)` where `V` is the disjoint set of HOLE
  identifiers. Each non-HOLE leaf is either a literal from `D_T` or
  a reference to a value in `Σ`.
- **H — Hole annotations.** A function `H : V → SyntCtx × SemType ×
  Cardinality`, where:
  - `SyntCtx ∈ {value, identifier, fragment, structural}` is the
    grammatical role of the hole;
  - `SemType ∈ {string, integer, decimal, boolean, date, blob,
    enum(set)}` is the semantic type expected at the hole;
  - `Cardinality ∈ {one, many(bounded), many(unbounded)}` says
    whether the hole expands to one value, a fixed number, or an
    arbitrary list (e.g., `IN (?, ?, …, ?)`).
- **C — Constraints.** A finite set of constraint atoms over `V`:
  type constraints (`τ(v) ⊑ SemType(v)`), range/length constraints
  if derivable, equality constraints (`v_1 = v_2`), allow-list
  constraints (`v ∈ S` with `S ⊂ D_T`), and ordering constraints
  on lists.
- **Σ — Symbol environment.** A mapping from identifiers occurring
  in `G` to (a) their host-language definitions, and (b) the proof
  obligation that each such identifier is in `D_T` (i.e., a constant
  or value drawn from a finite allow-list). Identifiers that fail
  this obligation force `φ` to abstain (see §5).

`SyntCtx = value` holes are the only holes that may be bound to
`D_A`-valued runtime expressions. All other `SyntCtx` values force
either `D_T`-membership or abstention.

### 3.1 SIG schema for SQL (excerpt)

```
Query    ::= Select | Insert | Update | Delete
Select   ::= SELECT Projection FROM TableRef
             [WHERE Predicate] [ORDER_BY OrderList]
             [LIMIT Limit] [OFFSET Offset]
TableRef ::= ident(table)
Projection ::= STAR | Column+
Column   ::= ident(column) | <HOLE: identifier, enum(columns)>
Predicate ::= Atom (AND Atom)*
Atom     ::= Comparison | InExpr | LikeExpr
Comparison ::= Column CmpOp Value
InExpr   ::= Column IN '(' ValueList ')'
LikeExpr ::= Column LIKE Value
Value    ::= lit | <HOLE: value, SemType, one>
ValueList::= Value (',' Value)*       (* may be <HOLE: value, T, many> *)
Limit    ::= int | <HOLE: value, integer, one>
Offset   ::= int | <HOLE: value, integer, one>
```

Every other interpreter (shell, HTML, LDAP, XPath, template) has its
own schema in `core/iam/schemas/<interp>.json`.

## 4. Binding function φ

`φ` is a partial function from IAMs to **patches**:

$$
\varphi : \mathrm{IAM} \rightharpoonup \mathrm{Patch}(H)
$$

A **patch** is a host-language AST rewrite that replaces the original
sink call site with a sequence of statements producing the same
observable behavior on `D_T`-only inputs. `φ(A) = \bot` (abstention)
denotes "no sound binding exists in the current catalog".

`φ` is implemented as a finite catalog of **binders** `B_1, …, B_n`,
each of the form:

```
B_k = (Pattern_k, Rewrite_k, Pre_k, Post_k, Proof_k)
```

- `Pattern_k` is a SIG sub-graph schema with named placeholders.
- `Rewrite_k` is a host-language AST template referencing those
  placeholders.
- `Pre_k`, `Post_k` are checkable preconditions / postconditions
  expressed over the host AST (e.g., "a `Connection` is in scope",
  "imports for `PreparedStatement` are available", "the rewrite is
  inside a `try-with-resources` or equivalent").
- `Proof_k` is a (paper-level) argument that for any concrete
  instantiation, the rewrite satisfies the soundness criterion of §5.

`φ` matches each maximal sub-graph of `G` against the catalog (greedy,
left-to-right, deterministic tie-break) and emits the composed AST
rewrite if every hole is covered. If any hole remains uncovered, `φ
= ⊥`.

## 5. Soundness criterion

We say a patch `p = φ(A)` is **IAM-sound** for sink `f` iff:

> For all host-program states `σ` and for all assignments of value
> holes to values in `D_T ∪ D_A`,
>
> $$\llbracket P_I(\mathrm{exec}(p, \sigma)) \rrbracket_I(\sigma) \in
>   \mathrm{Intent}(A) \subseteq L_I \setminus \mathrm{Mal}_I .$$

Here `exec(p, σ)` is the runtime string the patched program would
have sent to the interpreter (if any), and `Intent(A)` is the set
of surface strings whose CSTs match the SIG `G` with HOLEs replaced
by `D_T ∪ D_A` values **only at value-position holes** and `D_T`-only
values at identifier-position holes.

**Sufficient structural condition (this is what we check in code):**

> A patch is IAM-sound if every `value` hole in `G` is realized in
> the rewritten host AST as an argument to a **parameterizing API
> call** of `Sinks_H,I` (e.g., `PreparedStatement.setX`,
> `ProcessBuilder(List<String>)`, `Element.textContent`,
> `LdapName.add`, `XPathVariableResolver`, etc.), and every
> `identifier`/`structural` hole is realized as a `D_T`-allow-list
> lookup that traps on miss.

This condition is decidable on the host AST and is what the validator
(stage G) re-checks structurally before accepting a patch.

## 6. Operational pipeline summary

Stages A–G of the IR-SAM pipeline are operations whose types are:

```
A: Code → 𝒫(Findings)                       (Sink Locator)
B: Findings × Code → 𝒫(Slice)               (Slice Extractor)
C: Slice → ParameterizedTemplate             (String-Construction Reconstructor)
D: ParameterizedTemplate × Interpreter
                       → IAM ∪ {⊥}           (Intent Parser)
E ≡ φ : IAM → Patch ∪ {⊥}                    (Safe-API Binder)
F: Patch × HostAST → HostAST'                (Patch Synthesis)
G: HostAST' → {accept, reject}               (Validator)
```

Composition `(G ∘ F ∘ E ∘ D ∘ C ∘ B ∘ A)` is the full system. The
soundness theorem of §5, applied pointwise to every accepted output
of `G`, is the system-level claim of the thesis.

## 7. Abstention discipline

`φ` is required to abstain (`⊥`) rather than emit an unsound patch
whenever any of the following hold:

1. A hole's `SyntCtx` is `identifier` or `structural` and `Σ` cannot
   prove the host expression is in `D_T`.
2. A hole's `SemType` cannot be matched by any available
   parameterizing API for the host framework (e.g., LIKE-pattern
   meta-character escaping when the driver does not support
   `escape` parameter).
3. `C` contains an unsatisfiable constraint after parse.
4. Stage C reports a non-empty residual ambiguity that the symbolic
   parser of stage D cannot resolve and the disambiguator (Phase 4)
   is not enabled.

The system explicitly preferring `⊥` over a wrong patch is the **core
ethical commitment** of IR-SAM and the primary differentiator from
LLM-driven repair.

## 8. Differences from existing formalisms

- vs. **PreparedStatement-only refactoring tools.** They check
  syntactic conditions on the host AST. IR-SAM operates on the
  intent of the interpreter string, allowing rewrites where the
  source query was constructed dynamically.
- vs. **Symbolic taint sanitization.** Sanitizers attempt to escape
  attacker bytes inside the interpreter's lexer. IR-SAM relocates
  attacker bytes out of the lexer's domain (into protocol-level
  parameter slots), which is provably stronger.
- vs. **LLM-based repair.** No semantic soundness guarantee is
  expressible; "looks-right" is not an invariant. IR-SAM's `⊥`
  rather than guess closes the false-positive failure mode.
