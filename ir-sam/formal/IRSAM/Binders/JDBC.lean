/-
# IRSAM.Binders.JDBC

Lean encoding of the JDBC family of binders (``binders/sql_jdbc.yaml``,
``binders/hibernate_hql.yaml``, ``binders/jpa.yaml``,
``binders/spring_jdbctemplate.yaml``, ``binders/mybatis.yaml``).

A binder is a partial function ``φ : SIG → Option (SafeCall × ParamList)``.
We mirror this with a Lean ``BinderResult`` and a non-effectful
specification (the actual rewriting lives in Python; here we just
state the *contract*).
-/
import IRSAM.Core.IAM
import IRSAM.Interpreters.SQL

namespace IRSAM.Binders.JDBC

open IRSAM.Core

/-- The output of a successful binder run on a SIG. -/
structure SafeCall where
  /-- The fully-qualified parameterizing API (``PreparedStatement.setString``,
  ``NamedParameterJdbcTemplate.queryForList``, …). Must lie in the
  binder's ``parameterizing_apis`` set. -/
  api          : String
  /-- The parameterized template string with placeholders. -/
  template     : String
  /-- The list of host expressions bound to each placeholder, in order. -/
  bindings     : List String
  deriving Repr

/-- The trusted parameterizing-API set for ``binders/sql_jdbc.yaml``.
This is the *declared* set from the YAML; if a binder violates this
set, the loader closure check rejects it before we ever reach the
soundness theorem. -/
def jdbcParameterizingApis : List String :=
  [ "PreparedStatement.setString"
  , "PreparedStatement.setInt"
  , "PreparedStatement.setLong"
  , "PreparedStatement.setBoolean"
  , "PreparedStatement.setDate"
  , "PreparedStatement.setBytes"
  , "NamedParameterJdbcTemplate.queryForList"
  , "NamedParameterJdbcTemplate.queryForObject"
  , "NamedParameterJdbcTemplate.update" ]

/-- A binder run is **well-formed** w.r.t. an IAM ``I`` when its safe
call uses only APIs from the binder's declared set, and the number of
bindings equals the number of value-holes in ``I``. -/
def WellFormed (I : IAM) (call : SafeCall) : Prop :=
  jdbcParameterizingApis.contains call.api = true ∧
  call.bindings.length =
    (I.holes.filter (fun h => h.ctx = SyntCtx.value)).length

/-- A trivial sanity lemma: the well-formedness predicate is decidable
(used by the audit bridge). -/
instance (I : IAM) (call : SafeCall) : Decidable (WellFormed I call) := by
  unfold WellFormed; exact inferInstance

end IRSAM.Binders.JDBC
