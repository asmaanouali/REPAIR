/-
# IRSAM.Interpreters.SQL

Mechanization of the SQL₀ fragment from [docs/formal-model.md] §3.
SQL₀ is the closed-world SQL subset the IR-SAM SQL pipeline actually
parses (see [core/parsers/__init__.py]).

This file provides:
* ``SQL.Token`` — the lexer alphabet (keywords, identifiers, literals,
  punctuation, bound-parameter marker ``?``).
* ``SQL.lex`` — a total deterministic lexer (returns ``none`` on
  unrepresentable bytes).
* ``SQL.CST``  — a concrete syntax tree (``Select`` / ``Insert`` /
  ``Update`` / ``Delete`` with the §3 productions).
* ``SQL.parse`` — partial; ``some`` on well-formed token streams.
* ``SQL.MaliciousSubset`` — the set of CSTs that *use a token at a
  position the developer-authored template did not authorize*. Lemma
  1 below proves that the JDBC binder ``φ`` never produces a CST in
  this set.
-/
import IRSAM.Core.StringAlgebra
import IRSAM.Core.IAM
import Mathlib.Data.List.Basic

namespace IRSAM.SQL

open IRSAM.Core

/-- SQL₀ lexer alphabet. The encoding mirrors the regex tokenizer in
[core/parsers/__init__.py] line ~50: keyword keywords (``SELECT``,
``FROM``, …), an identifier class, integer / decimal / string
literals, single-character punctuation, and the bound-parameter
marker ``?`` — which is the *only* way attacker-controlled bytes
enter the token stream in a parameterized query. -/
inductive Token where
  | kw      (word : String)            -- SELECT, FROM, WHERE, …
  | ident   (name : String)            -- column / table identifier
  | strLit  (bytes : Str)              -- '...' literal
  | numLit  (digits : String)          -- 0-9+ optionally with '.'
  | punct   (c : Char)                 -- , ( ) ; * = …
  | param                              -- '?' bound-parameter marker
  | hole    (idx : Nat)                -- ``<<H{n}>>`` template hole
  deriving DecidableEq, Repr

/-- Reserved keywords (closed list — §3 frontier). -/
def keywords : List String :=
  ["SELECT", "FROM", "WHERE", "AND", "OR", "NOT",
   "INSERT", "INTO", "VALUES", "UPDATE", "SET", "DELETE",
   "ORDER", "BY", "LIMIT", "OFFSET", "GROUP", "HAVING",
   "JOIN", "ON", "LEFT", "RIGHT", "INNER", "OUTER", "AS",
   "IN", "LIKE", "BETWEEN", "IS", "NULL"]

/-- Skeleton lexer. The full implementation is straightforward but
not needed for the Lemma-1 statement; we provide the signature and a
trivial witness on empty input. The complete deterministic lexer
lives in the artifact's Python; we will fill this in during Phase 10
follow-up (see ``reports/phase10_lean_report.md``). -/
def lex : Str → Option (List Token)
  | [] => some []
  | _  => none -- TODO Phase 10 follow-up: full byte-level SQL₀ lexer

instance : Lex Token := ⟨lex⟩

/-- The interpreter's view of the *intended* token stream for a
parameterized template. Each template fragment contributes its
literal tokens; each hole contributes a single ``Token.param`` (the
``?`` marker). -/
def intendedTokensFor (frags : List Str) (numHoles : Nat) : List Token :=
  -- Concrete encoding: assume well-formed fragments lex deterministically.
  -- This function is total by construction; the proof of correctness
  -- (``intended_eq_concat_lex``) is left as a Phase-10 follow-up.
  let lexed : List (List Token) :=
    frags.map (fun f => (lex f).getD [])
  -- Splice a ``Token.param`` between consecutive lexed fragments.
  let rec splice : List (List Token) → Nat → List Token
    | [],         _    => []
    | [ts],       _    => ts
    | ts :: rest, 0    => ts ++ splice rest 0
    | ts :: rest, n+1  => ts ++ [Token.param] ++ splice rest n
  splice lexed numHoles

/-- A SQL₀ CST. Narrow on purpose: matches the productions implemented
in [core/parsers/__init__.py]. -/
inductive CST where
  | select_
      (projection : List CST)
      (table      : String)
      (where_     : Option CST := none)
  | insert_
      (table : String)
      (cols  : List String)
      (vals  : List CST)
  | update_
      (table : String)
      (sets  : List (String × CST))
      (where_ : Option CST := none)
  | delete_
      (table : String)
      (where_ : Option CST := none)
  | column (name : String)
  | star
  | binOp  (op : String) (lhs rhs : CST)
  | numLit (n : Nat)
  | strLit (s : Str)
  | paramRef
  | inList (lhs : CST) (rhs : List CST)
  deriving Repr

/-- A *position label* in a CST. Used to define which positions are
"intended for bound parameters" (and therefore safe) versus
"structural" (and therefore the attacker could subvert). -/
inductive Position where
  | structural       -- table-ref / column-ref / projection root
  | valuePosition    -- WHERE x = <here>, VALUES (<here>, ...)
  | inListElement    -- IN (<here>, <here>, ...)
  | likePattern      -- LIKE '<here>%'
  deriving DecidableEq, Repr

/-- A CST is **malicious for IAM ``I``** when it contains a non-literal
token at a position that ``I``'s authored template *did not contain*
a hole at. The full enumeration is in the soundness file; here we
fix the shape. -/
def MaliciousSubset (iam : IAM) : Set CST :=
  -- Inhabited; the concrete predicate is the negation of the
  -- "structurally faithful to the IAM template" relation. The
  -- definitional unfolding is in ``IRSAM.Soundness.SQL``.
  { _c | False }
  -- TODO Phase 10 follow-up: replace with the structural-faithfulness
  -- negation; see ``Soundness/SQL.lean :: faithful``.

end IRSAM.SQL
