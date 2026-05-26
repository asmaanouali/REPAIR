"""IAM / SIG / soundness predicates (Phase 1 reference implementation).

This module is intentionally *small* and *executable* — it encodes the
abstract syntax of the SIG, the IAM data class, and the structural
soundness check from
:doc:`docs/formal-model.md` §5 ("Sufficient structural condition").
The Phase-2 parser/synthesizer/validator layers consume these types.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Sequence


class SyntCtx(str, Enum):
    VALUE = "value"
    IDENTIFIER = "identifier"
    FRAGMENT = "fragment"
    STRUCTURAL = "structural"


class SemType(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    DECIMAL = "decimal"
    BOOLEAN = "boolean"
    DATE = "date"
    BLOB = "blob"
    ENUM = "enum"


class Cardinality(str, Enum):
    ONE = "one"
    MANY_BOUNDED = "many.bounded"
    MANY_UNBOUNDED = "many.unbounded"


# --- SIG node algebra ---------------------------------------------------------


@dataclass(frozen=True)
class Hole:
    """A typed parameterization point in the SIG."""
    name: str
    ctx: SyntCtx
    sem: SemType
    card: Cardinality = Cardinality.ONE
    allowlist: tuple[str, ...] | None = None  # for ENUM / identifier


@dataclass(frozen=True)
class Literal:
    value: str


@dataclass(frozen=True)
class SIGNode:
    """Generic SIG node: kind + ordered children."""
    kind: str
    children: tuple["SIGNode | Hole | Literal", ...] = ()
    attrs: tuple[tuple[str, str], ...] = ()  # frozen key/value pairs


# --- IAM container ------------------------------------------------------------


@dataclass(frozen=True)
class Constraint:
    kind: Literal["type", "eq", "allowlist", "range"]
    payload: tuple[str, ...]


@dataclass(frozen=True)
class SymbolEntry:
    """One entry in the IAM symbol environment Σ."""
    name: str
    host_expr: str                  # textual host-language expression
    proven_in_DT: bool              # taint analysis result
    constant_value: str | None = None


@dataclass(frozen=True)
class IAM:
    sig: SIGNode
    holes: tuple[Hole, ...]
    constraints: tuple[Constraint, ...] = ()
    symbols: tuple[SymbolEntry, ...] = ()
    interpreter: str = "sql"

    def hole(self, name: str) -> Hole:
        for h in self.holes:
            if h.name == name:
                return h
        raise KeyError(name)


# --- Soundness predicate (structural check) -----------------------------------


@dataclass(frozen=True)
class HostRealization:
    """How a hole was realized in the host AST after stage F.

    For value holes: ``via = "parameterized-api"`` and ``api`` records
    the safe API used (e.g. "PreparedStatement.setString").
    For identifier holes: ``via = "allowlist-lookup"``.
    For literals: ``via = "literal-in-template"``.
    """
    hole_name: str
    via: Literal["parameterized-api", "allowlist-lookup", "literal-in-template"]
    api: str | None = None


def structurally_sound(
    iam: IAM,
    realizations: Sequence[HostRealization],
    parameterizing_apis: set[str],
) -> tuple[bool, list[str]]:
    """Decide the §5 sufficient structural condition.

    Returns (ok, reasons). When ok is False, *reasons* is non-empty
    and explains why the patch should be rejected (used both inside
    the binder during synthesis and in stage G's structural re-check).
    """
    reasons: list[str] = []
    by_name = {r.hole_name: r for r in realizations}

    for h in iam.holes:
        r = by_name.get(h.name)
        if r is None:
            reasons.append(f"hole {h.name!r} not realized in host AST")
            continue
        if h.ctx is SyntCtx.VALUE:
            if r.via != "parameterized-api":
                reasons.append(
                    f"value-hole {h.name!r} not bound via a parameterized API "
                    f"(got via={r.via!r})"
                )
            elif r.api not in parameterizing_apis:
                reasons.append(
                    f"value-hole {h.name!r} bound via {r.api!r} which is not "
                    f"in the trusted parameterizing-API set"
                )
        elif h.ctx in (SyntCtx.IDENTIFIER, SyntCtx.STRUCTURAL):
            if r.via != "allowlist-lookup":
                reasons.append(
                    f"identifier/structural hole {h.name!r} not realized via an "
                    f"allow-list lookup (got via={r.via!r})"
                )
        # FRAGMENT holes are intentionally not yet supported in MVP

    # Identifier symbols must be proven in D_T.
    for s in iam.symbols:
        if not s.proven_in_DT:
            reasons.append(f"symbol {s.name!r} ({s.host_expr!r}) not proven in D_T")

    return (not reasons, reasons)
