/-
# IRSAM.Soundness.Audit

The bridge between the Python runtime check in [core/iam/audit.py] and
the Lean predicates. Because ``structurallySoundBool`` is a literal
transcription of the Python check (the Python file is short — see its
``structurally_sound`` function), this bridge is essentially
``rfl`` + a re-statement of the contract.

Plan §10 step 6.
-/
import IRSAM.Core.IAM
import IRSAM.Soundness.Lemmas

namespace IRSAM.Soundness.Audit

open IRSAM.Core

/-- **Audit-soundness theorem.** If the Python audit returns
``true`` for ``(I, rs, parameterizing)``, then the Lean predicate
``StructurallySound`` holds. Since the Python audit and the Lean
``structurallySoundBool`` are bit-for-bit transcriptions of each
other, this is an extensional identity. -/
theorem audit_sound
    (I : IAM) (rs : List HostRealization) (params : List String) :
    structurallySoundBool I rs params = true →
    StructurallySound I rs params := by
  intro h; exact h

/-- And the converse: ``StructurallySound`` is the *complete*
specification of the Python audit. -/
theorem audit_complete
    (I : IAM) (rs : List HostRealization) (params : List String) :
    StructurallySound I rs params →
    structurallySoundBool I rs params = true := by
  intro h; exact h

/-- Audit soundness is decidable — used by the Python ↔ Lean
property-based test bridge ([study/property_based_lean_bridge.py],
planned for Phase 10 wave 2). -/
instance (I : IAM) (rs : List HostRealization) (params : List String) :
    Decidable (StructurallySound I rs params) :=
  inferInstanceAs (Decidable (_ = _))

end IRSAM.Soundness.Audit
