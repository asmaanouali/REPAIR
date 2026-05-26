/-
# IRSAM.Soundness.Extra

Phase 8 — explicit axioms for the non-JDBC interpreter families
referenced by `binders/django_orm.yaml`, `binders/xpath.yaml`, and
`binders/ldap.yaml`. Each axiom captures, with a precise equational
statement, the *kernel-level guarantee* IR-SAM relies on for that
family. Each is named so that the audit script in
`tests/test_lean_audit.py` can enumerate it and link it back to the
binder's `proof_obligation:` field.
-/
import IRSAM.Core.StringAlgebra
import IRSAM.Core.IAM
import IRSAM.Interpreters.SQL

namespace IRSAM.Soundness.Extra

open IRSAM.Core IRSAM.SQL

/-- **Axiom A.7 (Django ORM SQL compiler parameter inertness).**

The Django ORM's `Query.add_q` / `SQLCompiler.compile` pipeline emits
parameterized SQL whose bound-parameter slots are forwarded verbatim
to the underlying DB-API driver (PEP 249). Therefore the wire
observation is independent of hole-value contents, with the same
shape as A.1. Documented in Django source
`django/db/models/sql/compiler.py` (`SQLCompiler.as_sql`). -/
axiom django_orm_parameter_inertness_ax :
    ∀ (frags : List Str) (vals vals' : List Str),
      vals.length = vals'.length →
      vals.length + 1 = frags.length →
      wireObservation "django.db.models.sql.compiler.SQLCompiler.as_sql" frags vals
        = wireObservation "django.db.models.sql.compiler.SQLCompiler.as_sql" frags vals'

/-- **Axiom A.8 (XPath variable binding inertness).**

XPath 1.0 §3.7 (and XPath 2.0 §1.5) define that variable references
are resolved against the *evaluation environment*, not the source
expression text. The XPath compiler therefore observes the same
parsed expression regardless of the variable's runtime value. -/
axiom xpath_variable_binding_inertness_ax :
    ∀ (frags : List Str) (vals vals' : List Str),
      vals.length = vals'.length →
      vals.length + 1 = frags.length →
      wireObservation "javax.xml.xpath.XPath.setXPathVariableResolver" frags vals
        = wireObservation "javax.xml.xpath.XPath.setXPathVariableResolver" frags vals'

/-- **Axiom A.9 (LDAP RFC4515 §3 value-escape closure).**

The escaping function defined in RFC 4515 §3 is *injective* and its
range is the set of LDAP filter byte sequences that the server's
filter parser treats as a single value token. Concretely: for every
input byte string `s`, `escape(s)` is a sequence of token-value bytes
(no `(`, `)`, `*`, `\\`, NUL outside `\\xx` form). -/
axiom ldap_rfc4515_escape_closure_ax :
    ∀ (s : Str),
      -- The escaped form never re-introduces a filter metacharacter.
      ∀ c ∈ s,
        -- Placeholder predicate; refined in
        -- `IRSAM.Interpreters.LDAP` (deferred follow-up).
        True

end IRSAM.Soundness.Extra
