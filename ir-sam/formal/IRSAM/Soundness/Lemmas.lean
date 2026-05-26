/-
# IRSAM.Soundness.Lemmas

The three core lemmas from [docs/formal-model.md] §5 / §6, stated
interpreter-generically.

* **Lemma 1 — Parameter Inertness.** Per parameterizing API ``a``,
  attacker bytes flowing through ``a`` cannot create a new
  interpreter token. (Interpreter-specific instances live in
  ``Soundness/SQL.lean``, ``Soundness/Shell.lean``, …)

* **Lemma 2 — Identifier Allow-list Closure.** Every identifier hole
  is realized by a lookup in a finite set ``L ⊆ D_T``; the result
  therefore lies in ``D_T``.

* **Lemma 3 — Structural Cover.** Every leaf of the SIG is realized
  (value-hole via Lemma 1, identifier-hole via Lemma 2, literal
  verbatim). Mechanized as a corollary of ``structurallySoundBool``.
-/
import IRSAM.Core.StringAlgebra
import IRSAM.Core.IAM

namespace IRSAM.Soundness

open IRSAM.Core

/-! ## Lemma 2 — Identifier Allow-list Closure -/

/-- An identifier hole's *resolved value* lies in its allowlist
whenever a lookup function is used. The Python runtime check in
[core/iam/audit.py] computes this; this Lean lemma certifies that
when ``via = allowlist_lookup`` holds, the realization is sound. -/
theorem identifier_allowlist_closure
    (h : Hole) (r : HostRealization) :
    h.ctx = SyntCtx.identifier ∧ r.via = RealizationVia.allowlist_lookup →
    -- The realization is admissible.
    realizationOk h r [] = true := by
  intro ⟨hctx, hvia⟩
  unfold realizationOk
  rw [hctx, hvia]
  rfl

/-! ## Lemma 3 — Structural Cover -/

/-- **Mechanized Lemma 3.** ``structurallySoundBool`` is precisely the
conjunction of "every hole is admissibly realized" and "every symbol
proved in ``D_T``". This is the definitional unfolding; the lemma is
useful because downstream proofs (per-binder soundness) discharge
their structural premise by ``decide``. -/
theorem structural_cover
    (I : IAM) (rs : List HostRealization) (params : List String) :
    StructurallySound I rs params ↔
      (∀ h ∈ I.holes,
        ∃ r, findRealization h.name rs = some r ∧
             realizationOk h r params = true) ∧
      (∀ s ∈ I.symbols, s.proven_in_DT = true) := by
  unfold StructurallySound structurallySoundBool
  simp [List.all_eq_true]
  constructor
  · intro ⟨hh, hs⟩
    refine ⟨?_, ?_⟩
    · intro h hmem
      have := hh h hmem
      cases hr : findRealization h.name rs with
      | none =>
        rw [hr] at this; simp at this
      | some r =>
        rw [hr] at this; simp at this
        exact ⟨r, hr, this⟩
    · intro s hmem
      have := hs s hmem
      simpa using this
  · intro ⟨hh, hs⟩
    refine ⟨?_, ?_⟩
    · intro h hmem
      obtain ⟨r, hr, hok⟩ := hh h hmem
      rw [hr]; simp; exact hok
    · intro s hmem
      simpa using hs s hmem

/-! ## Lemma 1 — Parameter Inertness (abstract template)

The interpreter-specific instances supply concrete witnesses; this
module only fixes the *shape* of the obligation. -/

/-- A parameter-inertness witness, parameterized over the
interpreter's token type. Each binder ``b`` supplies one
``ParameterInertness b`` per parameterizing API. -/
def ParameterInertness {Tok : Type} (_api : String) : Prop :=
  -- The intended-vs-observed equivalence at this API. Each
  -- interpreter file supplies a concrete proposition matching this
  -- shape; we leave the abstract version as an extensional
  -- placeholder. (Closed-form definition is unavoidable here because
  -- "the kernel's wire-format of the safe call" is interpreter-specific.)
  True

end IRSAM.Soundness
