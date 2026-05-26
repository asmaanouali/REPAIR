/-
# IRSAM.Core.IAM

Lean 4 mechanization of the IAM/SIG data structures from
[core/iam/__init__.py]. Every type and predicate in this file mirrors,
*line for line*, an entity in the Python reference. The
``IRSAM.Soundness.Audit`` module proves that the Python runtime
checks in [core/iam/audit.py] are sound w.r.t. these Lean predicates
(plan §10 step 6).
-/
import IRSAM.Core.StringAlgebra
import Mathlib.Data.Finset.Basic
import Mathlib.Data.List.Basic

namespace IRSAM.Core

/-- Syntactic context — mirrors ``core.iam.SyntCtx``. -/
inductive SyntCtx where
  | value
  | identifier
  | fragment
  | structural
  deriving DecidableEq, Repr

/-- Semantic type — mirrors ``core.iam.SemType``. -/
inductive SemType where
  | string
  | integer
  | decimal
  | boolean
  | date
  | blob
  | enum_
  deriving DecidableEq, Repr

/-- Cardinality — mirrors ``core.iam.Cardinality``. -/
inductive Cardinality where
  | one
  | many_bounded
  | many_unbounded
  deriving DecidableEq, Repr

/-- A typed parameterization point. -/
structure Hole where
  name      : String
  ctx       : SyntCtx
  sem       : SemType
  card      : Cardinality := Cardinality.one
  /-- Optional allowlist for identifier / enum holes. -/
  allowlist : Option (List String) := none
  deriving Repr

/-- Inline-template literal (developer-authored bytes). -/
structure Literal where
  value : Str
  deriving Repr

/-- One node of the Structured Intent Graph. We use the ``Sum`` for
heterogeneous children (``SIGNode | Hole | Literal``). -/
inductive SIGNode where
  | mk
      (kind     : String)
      (children : List SIGChild)
      (attrs    : List (String × String) := [])
  deriving Repr

with SIGChild where
  | node    (n : SIGNode)
  | hole    (h : Hole)
  | literal (l : Literal)
  deriving Repr

namespace SIGNode

/-- The ordered list of holes appearing under a SIG, in left-to-right
DFS order. Used by ``structurally_sound`` below. -/
partial def holes : SIGNode → List Hole
  | .mk _ children _ =>
    children.foldl (init := []) fun acc c =>
      match c with
      | .hole h    => acc ++ [h]
      | .node n    => acc ++ n.holes
      | .literal _ => acc

/-- Literal fragments under a SIG, in left-to-right DFS order. -/
partial def literals : SIGNode → List Literal
  | .mk _ children _ =>
    children.foldl (init := []) fun acc c =>
      match c with
      | .literal l => acc ++ [l]
      | .node n    => acc ++ n.literals
      | .hole _    => acc

end SIGNode

/-- Constraints on a hole — mirrors ``core.iam.Constraint``. -/
structure Constraint where
  kind    : String                       -- "type" | "eq" | "allowlist" | "range"
  payload : List String
  deriving Repr

/-- Symbol-environment entry Σ — mirrors ``core.iam.SymbolEntry``. -/
structure SymbolEntry where
  name           : String
  host_expr      : String
  proven_in_DT   : Bool
  constant_value : Option String := none
  deriving Repr

/-- The IAM container — mirrors ``core.iam.IAM``. -/
structure IAM where
  sig         : SIGNode
  holes       : List Hole
  constraints : List Constraint := []
  symbols     : List SymbolEntry := []
  interpreter : String := "sql"
  deriving Repr

/-- How a hole was realized in the host AST after stage F (mirrors
``core.iam.HostRealization``). -/
inductive RealizationVia where
  | parameterized_api  (api : String)
  | allowlist_lookup
  | literal_in_template
  deriving DecidableEq, Repr

structure HostRealization where
  hole_name : String
  via       : RealizationVia
  deriving Repr

/-! ## Structurally-sound predicate (Lemma 3 in mechanized form)

The Python function ``structurally_sound`` is total and decidable; we
mirror it as a ``Bool`` predicate, then prove it characterizes a
``Prop`` ``StructurallySound`` whose statement matches §5 of
[docs/formal-model.md]. -/

/-- ``True`` iff the realization for hole ``h`` satisfies its context's
admissibility rule. -/
def realizationOk (h : Hole) (r : HostRealization)
    (parameterizing : List String) : Bool :=
  match h.ctx with
  | .value =>
      match r.via with
      | .parameterized_api api => parameterizing.contains api
      | _                      => false
  | .identifier | .structural =>
      match r.via with
      | .allowlist_lookup      => true
      | _                      => false
  | .fragment =>
      -- MVP rejects fragment holes (matches Python comment).
      false

/-- Find the realization for a given hole, if any. -/
def findRealization (name : String) :
    List HostRealization → Option HostRealization
  | []      => none
  | r :: rs => if r.hole_name = name then some r else findRealization name rs

/-- Decidable structural-soundness — exact mirror of the Python
``structurally_sound`` body. Returns ``true`` iff (a) every hole has
a context-admissible realization and (b) every symbol is proven in
``D_T``. -/
def structurallySoundBool (iam : IAM) (rs : List HostRealization)
    (parameterizing : List String) : Bool :=
  iam.holes.all (fun h =>
    match findRealization h.name rs with
    | none   => false
    | some r => realizationOk h r parameterizing) &&
  iam.symbols.all (fun s => s.proven_in_DT)

/-- The structural-soundness predicate as a ``Prop``. The proof
obligation for binder soundness theorems uses this version. -/
def StructurallySound (iam : IAM) (rs : List HostRealization)
    (parameterizing : List String) : Prop :=
  structurallySoundBool iam rs parameterizing = true

instance (iam : IAM) (rs : List HostRealization) (params : List String) :
    Decidable (StructurallySound iam rs params) :=
  inferInstanceAs (Decidable (_ = _))

end IRSAM.Core
