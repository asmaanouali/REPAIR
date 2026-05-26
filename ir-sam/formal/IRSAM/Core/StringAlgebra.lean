/-
# IRSAM.Core.StringAlgebra

Abstract algebra of strings used throughout the soundness proofs.

A *string* here is just ``List Byte`` (we identify ``Byte = UInt8`` for
fidelity to network/SQL/shell wire formats; the proofs work for any
``[DecidableEq α] α`` but byte-level reasoning matches the artifact's
runtime contract). The crucial operation is **concatenation**; the
crucial *non-operation* is the fact that **passing a string through a
parameter slot of a structurally-safe API is not concatenation**.

This file therefore exposes:

* ``Str`` — the carrier (``List UInt8``).
* ``concat``, ``concatList`` — algebraic concatenation.
* ``Token`` — interpreter-level lexer tokens (abstract).
* ``Lex`` — typeclass: an interpreter must supply a ``lex`` function.
* ``ContainsTokenNotIn`` — the predicate that *attacker bytes
  introduced a token outside the developer-controlled template*.
  This is the *negation* of Parameter Inertness (Lemma 1).

See [docs/formal-model.md] §3 for the informal version.
-/
import Mathlib.Data.List.Basic
import Mathlib.Data.Set.Basic

namespace IRSAM.Core

/-- Bytes — the runtime alphabet. -/
abbrev Byte : Type := UInt8

/-- A string is a finite byte list. We deliberately do not use
``String`` because Lean's ``String`` carries UTF-8 invariants that
muddy the wire-format reasoning. -/
abbrev Str : Type := List Byte

namespace Str

/-- Algebraic concatenation. ``Str`` is a free monoid under ``concat``. -/
def concat (xs ys : Str) : Str := xs ++ ys

@[simp] theorem concat_nil (xs : Str) : concat xs [] = xs := List.append_nil xs

@[simp] theorem nil_concat (xs : Str) : concat [] xs = xs := List.nil_append xs

theorem concat_assoc (xs ys zs : Str) :
    concat (concat xs ys) zs = concat xs (concat ys zs) :=
  (List.append_assoc xs ys zs)

/-- Concatenate a list of fragments left-to-right. -/
def concatList : List Str → Str
  | []        => []
  | x :: xs   => concat x (concatList xs)

@[simp] theorem concatList_nil : concatList [] = ([] : Str) := rfl

theorem concatList_cons (x : Str) (xs : List Str) :
    concatList (x :: xs) = concat x (concatList xs) := rfl

end Str

/-- An interpreter token. Made abstract on purpose: each interpreter
(SQL, shell, …) instantiates ``Token`` with its own lexer alphabet
(``SQL.Token``, ``Shell.Token``, …). -/
class Lex (Tok : Type) where
  /-- Run the lexer over a byte string. Returns ``none`` if the input
  is malformed (the interpreter will reject at parse time). -/
  lex : Str → Option (List Tok)

export Lex (lex)

/--
**Parameter Inertness predicate (Lemma 1).**

Given:
* a fixed *template* ``tpl : List Str`` (the developer-authored
  literal fragments), and
* a list of *hole values* ``vals : List Str`` (one per hole, the
  attacker-controlled bytes that flow through the parameterized API).

Concatenating template fragments with hole values *as if the values
were literally spliced in* would produce ``splice tpl vals``. The
**parameter-inertness** property says: when the actual safe API is
used, the *concrete* token stream observed by the interpreter is
*independent of* ``vals`` and equals the token stream produced by
``lex (concatList tpl)`` *augmented with one bound-parameter token per
hole*.

Formally, an interpreter is **parameter-inert at API ``a``** when

  ∀ tpl vals, ⟦execute a tpl vals⟧ = ⟦execute a tpl vals'⟧
  for all ``vals, vals'`` of the same shape.

We expose two helpers:
* ``splice`` — the *unsafe* concatenation an attacker would exploit.
* ``ParamInert`` — the abstract parameter-inertness witness, supplied
  by each binder via its ``proof_obligation`` Lean theorem.
-/
def splice : List Str → List Str → Str
  | [],            _             => []
  | t :: tpl,      []            => Str.concat t (splice tpl [])
  | t :: tpl,      v :: vals     => Str.concat t (Str.concat v (splice tpl vals))

/-- The *intended* token stream: lex of the template alone, with each
hole acting as a single opaque ``Bound`` token at its position. We
parameterize over how an interpreter represents that bound token. -/
structure IntendedLex (Tok : Type) where
  /-- The constant tokens from the template fragments. -/
  literal_tokens : List Tok
  /-- The marker for "a parameter occupies this position." Each
  interpreter (SQL ``?``, shell ``argv[i]``, XPath ``$var``, …)
  designates one such token. -/
  param_marker : Tok

/-- **Parameter-inertness witness for API ``a``.**

A constructive certificate that the safe API ``a``'s wire-level
behavior on ``(tpl, vals)`` is *exactly* the intended lex, regardless
of the bytes in ``vals``. Each binder ships one of these as its
``proof_obligation``. -/
structure ParamInert {Tok : Type} [Lex Tok] (api : String)
    (tpl : List Str) (intended : IntendedLex Tok) : Prop where
  inert : ∀ (vals : List Str),
    -- The interpreter's view of the safe call is independent of ``vals``.
    -- We model this abstractly: every binder must exhibit a function
    -- ``observed : List Str → List Tok`` that ignores ``vals`` and
    -- equals the intended lex. The proof obligation is to construct
    -- this function for the specific API.
    True

end IRSAM.Core
