import Lake
open Lake DSL

package «irsam» where
  -- IR-SAM Phase 10: Lean 4 mechanization of the IAM soundness theorem.
  -- See [docs/soundness-proof.md] and [reports/phase10_lean_report.md].
  leanOptions := #[
    ⟨`pp.unicode.fun, true⟩,
    ⟨`autoImplicit, false⟩
  ]

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.10.0"

@[default_target]
lean_lib «IRSAM» where
  -- Top-level module collecting every interpreter / binder / proof.
  -- Build with: ``lake build``
  -- Audit with: ``../scripts/check_no_sorry.sh``
  roots := #[`IRSAM]
