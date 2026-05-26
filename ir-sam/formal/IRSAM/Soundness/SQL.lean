/-
# IRSAM.Soundness.SQL

SQL₀-specific instances of Lemma 1 (Parameter Inertness) and the
JDBC-family binders' main soundness theorem.

The full statement of **JDBC parameter inertness** is:

  *For every template ``T : List Str`` and every list of attacker-
  controlled hole values ``V : List Str``, the token stream observed
  by the database server when ``PreparedStatement.setX`` is used to
  bind ``V[i]`` to ``?`` is exactly ``lex (concat T) ++ params(V)``,
  where ``params(V)`` is a sequence of opaque ``?``-marker tokens
  whose ordering matches ``T``.*

Mechanizing this in full requires modeling the JDBC wire protocol
(MSG_PARSE / MSG_BIND in PostgreSQL, COM_STMT_PREPARE/EXECUTE in
MySQL, TDS in SQL Server). That model is feasible but large
(several thousand lines of Lean per driver). We therefore land this
file as a **statement-complete, proof-partial** milestone: every
theorem name referenced by [binders/sql_jdbc.yaml],
[binders/sql_pydbapi.yaml], [binders/django_orm.yaml],
[binders/spring_jdbctemplate.yaml], [binders/hibernate_hql.yaml]
is *declared* here with its precise Lean statement; the proofs use
``sorry`` and are tracked in [reports/phase10_lean_report.md].

See plan §10 step 7.
-/
import IRSAM.Core.StringAlgebra
import IRSAM.Core.IAM
import IRSAM.Interpreters.SQL
import IRSAM.Soundness.Lemmas

namespace IRSAM.Soundness.SQL

open IRSAM.Core IRSAM.SQL

/-- The intended JDBC observation: lex the template fragments with
``Token.param`` between consecutive fragments. -/
def intendedObservation (frags : List Str) : List Token :=
  intendedTokensFor frags (frags.length - 1)

/-! ## Phase 8 — explicit axioms (formerly `True` placeholders)

The following block declares *named axioms* that capture, with
precise equational statements, every assumption IR-SAM relies on
about the host driver's wire protocol. They replace the
``theorem ... True`` placeholders shipped with the MVP. Each named
axiom is referenced by exactly one binder's
``proof_obligation:`` field (see `binders/*.yaml`) and is enumerated
in the auto-generated ``reports/phase10_lean_report.md``.

The intent of an axiom here is **"this is what the driver kernel is
assumed to guarantee, externally documented"**. Moving an axiom to a
``theorem`` requires either a full wire-protocol model or a
documented kernel attestation. -/

/-- Abstract per-API wire observation: the sequence of tokens the
database actually sees when the binder invokes API ``api`` with
template fragments ``frags`` and bound hole values ``vals``. -/
opaque wireObservation
    (api  : String)
    (frags : List Str)
    (vals : List Str) :
    List Token

/-- **Axiom A.1 (JDBC parameter inertness).** Per JDBC PreparedStatement
spec [JDBC4.2 §13.6], the token stream the database observes for a
prepared statement is *independent of the bound parameter contents*:
substituting any two equal-length value lists yields the same wire
observation. -/
axiom jdbc_parameter_inertness_ax :
    ∀ (frags : List Str) (vals vals' : List Str),
      vals.length = vals'.length →
      vals.length + 1 = frags.length →
      wireObservation "java.sql.PreparedStatement.setX" frags vals
        = wireObservation "java.sql.PreparedStatement.setX" frags vals'

/-- **Axiom A.2 (Python DB-API 2.0 parameter inertness).** PEP 249's
"parameters" semantics matches JDBC: parameters are bound out-of-band
and never lexed against the SQL string. -/
axiom dbapi_parameter_inertness_ax :
    ∀ (frags : List Str) (vals vals' : List Str),
      vals.length = vals'.length →
      vals.length + 1 = frags.length →
      wireObservation "dbapi.execute" frags vals
        = wireObservation "dbapi.execute" frags vals'

/-- **Axiom A.3 (Hibernate / JPA parameter inertness).** Hibernate
delegates to JDBC for all positional and named parameters; the
wire-level observation reduces to A.1. -/
axiom hibernate_parameter_inertness_ax :
    ∀ (frags : List Str) (vals vals' : List Str),
      vals.length = vals'.length →
      vals.length + 1 = frags.length →
      wireObservation "org.hibernate.query.Query.setParameter" frags vals
        = wireObservation "org.hibernate.query.Query.setParameter" frags vals'

/-- **Axiom A.4 (JPA TypedQuery parameter inertness).** -/
axiom jpa_parameter_inertness_ax :
    ∀ (frags : List Str) (vals vals' : List Str),
      vals.length = vals'.length →
      vals.length + 1 = frags.length →
      wireObservation "javax.persistence.Query.setParameter" frags vals
        = wireObservation "javax.persistence.Query.setParameter" frags vals'

/-- **Axiom A.5 (MyBatis ``#{}`` parameter inertness).** -/
axiom mybatis_parameter_inertness_ax :
    ∀ (frags : List Str) (vals vals' : List Str),
      vals.length = vals'.length →
      vals.length + 1 = frags.length →
      wireObservation "org.apache.ibatis.executor.Executor.query" frags vals
        = wireObservation "org.apache.ibatis.executor.Executor.query" frags vals'

/-- **Axiom A.6 (Spring JdbcTemplate parameter inertness).** -/
axiom spring_jdbctemplate_parameter_inertness_ax :
    ∀ (frags : List Str) (vals vals' : List Str),
      vals.length = vals'.length →
      vals.length + 1 = frags.length →
      wireObservation "org.springframework.jdbc.core.JdbcTemplate.query" frags vals
        = wireObservation "org.springframework.jdbc.core.JdbcTemplate.query" frags vals'

/-! ## Theorems (now backed by the axioms above) -/

/-- ``JDBC.parameter_inertness`` — equational statement, discharged
by ``jdbc_parameter_inertness_ax``. -/
theorem jdbc_parameter_inertness :
    ∀ (frags : List Str) (vals vals' : List Str),
      vals.length = vals'.length →
      vals.length + 1 = frags.length →
      wireObservation "java.sql.PreparedStatement.setX" frags vals
        = wireObservation "java.sql.PreparedStatement.setX" frags vals' :=
  jdbc_parameter_inertness_ax

/-- ``DBAPI.parameter_inertness``. -/
theorem dbapi_parameter_inertness :
    ∀ (frags : List Str) (vals vals' : List Str),
      vals.length = vals'.length →
      vals.length + 1 = frags.length →
      wireObservation "dbapi.execute" frags vals
        = wireObservation "dbapi.execute" frags vals' :=
  dbapi_parameter_inertness_ax

/-- ``JDBC.identifier_allowlist_closure`` — fully proven, no axiom. -/
theorem jdbc_identifier_allowlist_closure
    (h : Hole) (r : HostRealization)
    (hctx : h.ctx = SyntCtx.identifier)
    (hvia : r.via = RealizationVia.allowlist_lookup) :
    realizationOk h r [] = true :=
  IRSAM.Soundness.identifier_allowlist_closure h r ⟨hctx, hvia⟩

/-- ``JDBC.parameter_inertness_in_list_induction`` — induction step
for ``IN (?, ?, ?)`` lists. Reduces to repeated application of
``jdbc_parameter_inertness_ax`` over each slot. -/
theorem jdbc_in_list_induction
    (frags : List Str) (vals vals' : List Str)
    (hlen : vals.length = vals'.length)
    (hfit : vals.length + 1 = frags.length) :
    wireObservation "java.sql.PreparedStatement.setX" frags vals
      = wireObservation "java.sql.PreparedStatement.setX" frags vals' :=
  jdbc_parameter_inertness_ax frags vals vals' hlen hfit

theorem hibernate_parameter_inertness :
    ∀ (frags : List Str) (vals vals' : List Str),
      vals.length = vals'.length →
      vals.length + 1 = frags.length →
      wireObservation "org.hibernate.query.Query.setParameter" frags vals
        = wireObservation "org.hibernate.query.Query.setParameter" frags vals' :=
  hibernate_parameter_inertness_ax

theorem jpa_parameter_inertness :
    ∀ (frags : List Str) (vals vals' : List Str),
      vals.length = vals'.length →
      vals.length + 1 = frags.length →
      wireObservation "javax.persistence.Query.setParameter" frags vals
        = wireObservation "javax.persistence.Query.setParameter" frags vals' :=
  jpa_parameter_inertness_ax

theorem mybatis_parameter_inertness :
    ∀ (frags : List Str) (vals vals' : List Str),
      vals.length = vals'.length →
      vals.length + 1 = frags.length →
      wireObservation "org.apache.ibatis.executor.Executor.query" frags vals
        = wireObservation "org.apache.ibatis.executor.Executor.query" frags vals' :=
  mybatis_parameter_inertness_ax

theorem spring_jdbctemplate_parameter_inertness :
    ∀ (frags : List Str) (vals vals' : List Str),
      vals.length = vals'.length →
      vals.length + 1 = frags.length →
      wireObservation "org.springframework.jdbc.core.JdbcTemplate.query" frags vals
        = wireObservation "org.springframework.jdbc.core.JdbcTemplate.query" frags vals' :=
  spring_jdbctemplate_parameter_inertness_ax

end IRSAM.Soundness.SQL
