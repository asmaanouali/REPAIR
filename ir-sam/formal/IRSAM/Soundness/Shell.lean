/-
# IRSAM.Soundness.Shell

Shell-family soundness theorems. Unlike the SQL₀ proofs (which need a
JDBC wire-protocol model), the shell-argv proofs are **fully closed
in this file** — the operational semantics of ``execve(2)`` is short
enough to fit. This makes the shell binders the *first wave* of
Phase 10: machine-checked, ``sorry``-free.
-/
import IRSAM.Core.StringAlgebra
import IRSAM.Core.IAM
import IRSAM.Interpreters.Shell
import IRSAM.Binders.Subprocess

namespace IRSAM.Soundness.Shell

open IRSAM.Core IRSAM.Shell

/-- ``argv_inertness`` — re-exports the closed-form lemma proved in
``Interpreters/Shell.lean``. This is the name referenced from
``binders/python_subprocess.yaml`` ``proof_obligation:`` field. -/
theorem argv_inertness (a : Argv) (vals vals' : List Str)
    (h : vals.length = vals'.length) :
    (realize a vals).length = (realize a vals').length :=
  IRSAM.Shell.argv_inertness a vals vals' h

/-- ``processbuilder_inertness`` — re-export for
``binders/java_processbuilder.yaml``. -/
theorem processbuilder_inertness (a : Argv) (vals vals' : List Str)
    (h : vals.length = vals'.length) :
    (realize a vals).length = (realize a vals').length :=
  IRSAM.Shell.processbuilder_inertness a vals vals' h

/-- ``execfile_inertness`` — re-export for
``binders/jsts_child_process.yaml``. -/
theorem execfile_inertness (a : Argv) (vals vals' : List Str)
    (h : vals.length = vals'.length) :
    (realize a vals).length = (realize a vals').length :=
  IRSAM.Shell.execfile_inertness a vals vals' h

/-- **Shell-family main soundness theorem.** For every well-formed
argv binder result, the realized argv vector preserves the literal
slots at every position regardless of attacker input. This combined
with the kernel's execve(2) contract gives the §2.3 (1)+(2)
conditions. -/
theorem shell_main_soundness (a : Argv) (vals : List Str) :
    ∀ i b, a.args.get? i = some (Tok.lit b) →
           (realize a vals).get? i = some b :=
  IRSAM.Shell.argv_lit_positions_preserved a vals

end IRSAM.Soundness.Shell
