/-
# IR-SAM — top-level module.

Importing this brings the entire mechanization into scope. Build with
``lake build IRSAM``. The acceptance gate (Phase 10 step 11) is

    ``scripts/check_no_sorry.sh`` exits 0
    and ``#print axioms`` on every public theorem lists only
    ``propext``, ``Classical.choice``, ``Quot.sound``.

Open tactics under ``IRSAM.Soundness.OpenObligations`` track every
``sorry`` placeholder by name so the audit script can enumerate them.
-/
import IRSAM.Core.StringAlgebra
import IRSAM.Core.IAM
import IRSAM.Interpreters.SQL
import IRSAM.Interpreters.Shell
import IRSAM.Binders.JDBC
import IRSAM.Binders.Subprocess
import IRSAM.Soundness.Lemmas
import IRSAM.Soundness.SQL
import IRSAM.Soundness.Shell
import IRSAM.Soundness.Audit
import IRSAM.Soundness.Theorem
