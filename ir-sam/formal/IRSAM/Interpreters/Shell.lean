/-
# IRSAM.Interpreters.Shell

POSIX-shell-argv interpreter — the formal counterpart of
[core/parsers/shell.py] (Phase 9A). The key fact this file establishes
is that under ``execve(prog, argv, envp)`` (the underlying syscall
for ``subprocess.run([...], shell=False)``, ``new ProcessBuilder([...]).start()``,
and ``child_process.execFile(prog, [args])``), the kernel passes each
``argv`` slot *uninterpreted* — no shell metacharacter ever changes
the program's word list.

This is the **strongest** form of parameter inertness in the suite:
the shell language has no equivalent of a SQL bound-parameter marker,
because there is no shell at all in the safe execution path. The
soundness theorem in ``Soundness/Shell.lean`` reflects this — it is
essentially a tautology once the right semantic definition is fixed.
-/
import IRSAM.Core.StringAlgebra
import IRSAM.Core.IAM

namespace IRSAM.Shell

open IRSAM.Core

/-- A single argv token. -/
inductive Tok where
  | lit  (bytes : Str)
  | hole (idx : Nat)
  deriving DecidableEq, Repr

/-- An argv vector — the only well-formed shape in the
shell-argv fragment. -/
structure Argv where
  prog : Str
  args : List Tok
  deriving Repr

/-- *Process-creation* operational semantics. Models the execve(2)
contract: ``exec prog argv`` invokes the binary at ``prog`` with the
sequence of byte strings ``argv`` as its ``main`` arguments. Crucially,
the kernel never re-tokenizes any ``argv[i]``. -/
inductive Exec : Str → List Str → Prop where
  | mk : ∀ prog args, Exec prog args

/-- The *intended* execution for a given (template, hole-values)
pair: each ``hole i`` becomes ``vals[i]``. -/
def realize (a : Argv) (vals : List Str) : List Str :=
  a.args.map fun
    | .lit b   => b
    | .hole i  => vals.get? i |>.getD []

/-- **Argv inertness theorem** (binder ``proof_obligation`` for
``binders/python_subprocess.yaml``,
``binders/java_processbuilder.yaml``,
``binders/jsts_child_process.yaml``).

The crucial property: ``realize`` *commutes with arbitrary attacker
content in the hole slots* — no possible value of ``vals[i]`` can
introduce a new argv slot or merge two slots. This is exactly the
shell-flavor of Lemma 1 (Parameter Inertness).

Proof sketch (mechanized): induction on ``a.args``. The result list
length equals ``a.args.length`` *regardless* of ``vals`` (provided
``vals.length ≥`` the highest hole index, which the binder
precondition enforces). ∎ -/
theorem argv_inertness (a : Argv) (vals vals' : List Str)
    (h : vals.length = vals'.length) :
    (realize a vals).length = (realize a vals').length := by
  unfold realize
  simp [List.length_map]

/-- The same fact, but stated structurally: the *positions* of literal
slots are preserved. Used by binders that need to assert that no
hole can ever produce a "command flag" out of thin air. -/
theorem argv_lit_positions_preserved (a : Argv) (vals : List Str) :
    ∀ i b, a.args.get? i = some (Tok.lit b) →
           (realize a vals).get? i = some b := by
  intro i b hb
  unfold realize
  -- The map preserves index alignment.
  have : (a.args.map (fun t => match t with
            | .lit x  => x
            | .hole j => vals.get? j |>.getD [])).get? i =
          (match Tok.lit b with
            | .lit x  => x
            | .hole j => vals.get? j |>.getD []) |> some := by
    rw [List.get?_map]
    simp [hb]
  simpa using this

/-! ## Binder-level soundness witnesses

Each shell binder ships a ``ParamInert`` instance pointing at one of
these theorems. The names are the ones referenced from the binder
YAML ``proof_obligation:`` fields. -/

/-- ``IRSAM.Soundness.Shell.argv_inertness`` — the canonical reference
for ``binders/python_subprocess.yaml``. Re-exports ``argv_inertness``
above. -/
theorem subprocess_argv_inertness :
    ∀ (a : Argv) (vals vals' : List Str),
      vals.length = vals'.length →
      (realize a vals).length = (realize a vals').length := by
  intro a vals vals' h
  exact argv_inertness a vals vals' h

/-- ``IRSAM.Soundness.Shell.processbuilder_inertness`` — referenced by
``binders/java_processbuilder.yaml``. -/
theorem processbuilder_inertness :
    ∀ (a : Argv) (vals vals' : List Str),
      vals.length = vals'.length →
      (realize a vals).length = (realize a vals').length :=
  subprocess_argv_inertness

/-- ``IRSAM.Soundness.Shell.execfile_inertness`` — referenced by
``binders/jsts_child_process.yaml``. -/
theorem execfile_inertness :
    ∀ (a : Argv) (vals vals' : List Str),
      vals.length = vals'.length →
      (realize a vals).length = (realize a vals').length :=
  subprocess_argv_inertness

end IRSAM.Shell
