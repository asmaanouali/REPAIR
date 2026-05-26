"""Stage E --- the binding function \u03c6.

\u03c6 walks the SIG, identifies value/identifier holes, and emits a
:class:`PatchPlan` describing how stage F should rewrite the host Java
AST. \u03c6 returns ``None`` (= \u22a5) when no sound binding exists, e.g.
when an identifier hole has no allow-list, or a value hole has a
semantic type unsupported by the catalog.

Phase 1 (binder runtime): \u03c6 now delegates matching and op-collection
to :mod:`core.binder.runtime`. The runtime drives setter selection,
identifier-allowlist guards, and IN-list expansion from the active
:class:`~core.binder.loader.BinderCatalog` rather than from a hardcoded
JDBC table. The MVP default catalog remains ``binders/sql_jdbc.yaml``;
non-JDBC catalogs (LDAP, XPath, MyBatis, ...) now exercise the same
machinery and produce a :class:`PatchPlan` whose ``setter_calls`` list
records the catalog-resolved API at each binding point.
"""

from __future__ import annotations

from dataclasses import dataclass

from core.binder.loader import BinderCatalog
from core.binder.runtime import (
    AllowlistGuardOp,
    InListExpandOp,
    ParamBindOp,
    _RuntimeAbstain,
    collect_ops,
    match_binder,
    render_template,
    short_method_for_api,
)
from core.iam import (
    IAM,
    Cardinality,
    Hole,
    HostRealization,
    Literal,
    SemType,
    SIGNode,
    SymbolEntry,
    SyntCtx,
)


# --- output data types --------------------------------------------------------


@dataclass(frozen=True)
class SetterCall:
    """One PreparedStatement.setX(idx, expr) call to emit in stage F."""

    param_index: int
    api: str  # "java.sql.PreparedStatement.setString"
    short_method: str  # "setString"
    host_expr: str  # Java expression text
    hole_name: str


@dataclass(frozen=True)
class AllowlistGuard:
    """An identifier-hole allow-list pre-substitution check."""

    hole_name: str
    host_expr: str
    allowlist_java_const: str  # name of the allow-list constant
    on_miss: str = "IllegalArgumentException"


@dataclass(frozen=True)
class PatchPlan:
    """The materialization of \u03c6 to be consumed by stage F."""

    prepared_template: str  # e.g. "SELECT * FROM users WHERE id = ?"
    setter_calls: tuple[SetterCall, ...]
    allowlist_guards: tuple[AllowlistGuard, ...]
    realizations: tuple[HostRealization, ...]
    catalog_id: str
    binder_ids_used: tuple[str, ...]
    proof_obligations: tuple[str, ...]


@dataclass(frozen=True)
class PhiAbstention:
    reason: str
    details: str = ""


# Legacy sem->setter map. Kept as a defensive fallback for bare Hole nodes
# that are not enclosed by a binder-matched SIG subtree (this never happens
# for well-formed SIGs produced by the standard parsers, but the fallback
# keeps the function total).
_SEM_TO_SETTER = {
    SemType.STRING:  ("setString",     "java.sql.PreparedStatement.setString"),
    SemType.INTEGER: ("setLong",       "java.sql.PreparedStatement.setLong"),
    SemType.DECIMAL: ("setBigDecimal", "java.sql.PreparedStatement.setBigDecimal"),
    SemType.BOOLEAN: ("setBoolean",    "java.sql.PreparedStatement.setBoolean"),
    SemType.DATE:    ("setTimestamp",  "java.sql.PreparedStatement.setTimestamp"),
    SemType.BLOB:    ("setObject",     "java.sql.PreparedStatement.setObject"),
    SemType.ENUM:    ("setString",     "java.sql.PreparedStatement.setString"),
}


def _placeholder_for_catalog(catalog: BinderCatalog) -> str:
    """Pick the SQL placeholder token for ``catalog`` (JDBC=``?``, psycopg2=``%s``...).

    The DSL allows catalogs to declare ``placeholder_styles`` per driver;
    we pick the one matching the framework, with sensible defaults.
    """
    raw = getattr(catalog, "placeholder_styles", None) or {}
    fw = (catalog.framework or "").lower()
    for driver, token in raw.items():
        if driver.lower() in fw:
            return token
    if catalog.interpreter == "sql":
        if catalog.host_language == "java":
            return "?"
        if catalog.host_language == "python":
            return "?"        # qmark is the safe default; DB-API specific
    return "?"


# --- core algorithm -----------------------------------------------------------


def apply_phi(
    sig: SIGNode,
    holes: tuple[Hole, ...],
    host_exprs: dict[str, str],
    catalog: BinderCatalog,
    *,
    allowlists: dict[str, str] | None = None,
) -> PatchPlan | PhiAbstention:
    """Bind every hole in ``sig`` and produce a patch plan.

    Implementation:
    * Outer/structural SIG nodes (``Select``, ``Where``, ``Projection``,
      ...) are rendered by :func:`_render_sig`.
    * Inner pattern nodes (``Comparison``, ``LikeExpr``, ``InExpr``,
      ``Limit``, ``OrderList``, ``XPathPredicateEq``, ``LdapEquality``,
      ...) are matched against ``catalog.binders``; on a match the
      binder's ``template_string`` drives output and its declared
      bindings drive setter/escape/guard selection.
    * Bare holes inside structural nodes (no enclosing binder match)
      fall back to a defensive sem->setter map so the function stays
      total even for partial catalogs.
    """
    allowlists = allowlists or {}
    setters: list[SetterCall] = []
    guards: list[AllowlistGuard] = []
    realizations: list[HostRealization] = []
    binder_ids: list[str] = []
    proofs: set[str] = set()
    param_index = 1
    placeholder = _placeholder_for_catalog(catalog)

    def emit_value_op(op: ParamBindOp | InListExpandOp) -> None:
        api = op.api
        host = op.host_expr
        short = short_method_for_api(api)
        if isinstance(op, InListExpandOp):
            setters.append(SetterCall(
                param_index=-1, api=api, short_method=short,
                host_expr=host, hole_name=op.hole_name,
            ))
            realizations.append(HostRealization(
                hole_name=op.hole_name, via="parameterized-api", api=api,
            ))
            proofs.add("Lemma 1 (Parameter inertness), induction step (lists).")
            return
        setters.append(SetterCall(
            param_index=op.param_index, api=api, short_method=short,
            host_expr=host, hole_name=op.hole_name,
        ))
        realizations.append(HostRealization(
            hole_name=op.hole_name, via="parameterized-api", api=api,
        ))
        proofs.add("Lemma 1 (Parameter inertness).")

    def emit_guard_op(op: AllowlistGuardOp) -> None:
        guards.append(AllowlistGuard(
            hole_name=op.hole_name,
            host_expr=op.host_expr,
            allowlist_java_const=op.allowlist_source,
        ))
        realizations.append(HostRealization(
            hole_name=op.hole_name, via="allowlist-lookup", api=None,
        ))
        proofs.add("Lemma 2 (Identifier allow-list closure).")

    def render(node: object) -> str:
        nonlocal param_index
        if isinstance(node, Literal):
            return node.value
        if isinstance(node, Hole):
            return _render_bare_hole(
                node, host_exprs, allowlists,
                setters, guards, realizations, proofs, binder_ids,
                param_index_box=[param_index],
                catalog=catalog,
            ) or _render_bare_hole_unreachable(node)
        if isinstance(node, SIGNode):
            # Try binder match first.
            match = match_binder(catalog, node)
            if match is not None:
                try:
                    ops, param_index = collect_ops(
                        match, catalog,
                        host_exprs=host_exprs,
                        allowlists=allowlists,
                        param_index=param_index,
                    )
                except _RuntimeAbstain as e:
                    raise _PhiAbstainSignal(str(e))
                for op in ops:
                    if isinstance(op, (ParamBindOp, InListExpandOp)):
                        emit_value_op(op)
                    elif isinstance(op, AllowlistGuardOp):
                        emit_guard_op(op)
                binder_ids.append(match.binder.id)
                if match.binder.proof_obligation:
                    proofs.add(match.binder.proof_obligation)
                return render_template(
                    match.binder.rewrite.get("template_string", ""),
                    match.bindings,
                    render_child=render,
                    placeholder_token=placeholder,
                    inlist_token=lambda nm: f"__INLIST_{nm}__",
                    guard_token=lambda nm: f"{{__GUARD_{nm}__}}",
                )
            return _render_sig(node, render)
        return ""

    try:
        prepared = render(sig)
    except _PhiAbstainSignal as e:
        return _abstention_from_signal(e.args[0])

    apis_used = {s.api for s in setters}
    if not apis_used.issubset(catalog.parameterizing_apis):
        bad = apis_used - catalog.parameterizing_apis
        return PhiAbstention("closure_violation",
                             f"APIs used by \u03c6 not in catalog: {sorted(bad)}")

    return PatchPlan(
        prepared_template=prepared.strip(),
        setter_calls=tuple(setters),
        allowlist_guards=tuple(guards),
        realizations=tuple(realizations),
        catalog_id=catalog.id,
        binder_ids_used=tuple(sorted(set(binder_ids))),
        proof_obligations=tuple(sorted(proofs)),
    )


def _abstention_from_signal(msg: str) -> PhiAbstention:
    """Map a :class:`_RuntimeAbstain` message to a typed ``PhiAbstention``."""
    if "no allow-list" in msg:
        return PhiAbstention("no_allowlist", msg)
    if "has no API for sem" in msg or "no_host_expr" in msg:
        return PhiAbstention("unsupported_sem", msg)
    if "not in parameterizing_apis" in msg:
        return PhiAbstention("closure_violation", msg)
    if "ctx" in msg and "not supported" in msg:
        return PhiAbstention("unsupported_ctx", msg)
    return PhiAbstention("phi_abstain", msg)


class _PhiAbstainSignal(Exception):
    """Internal: tunnel a runtime-abstain through the recursive renderer."""


def _render_bare_hole(
    node: Hole,
    host_exprs: dict[str, str],
    allowlists: dict[str, str],
    setters: list[SetterCall],
    guards: list[AllowlistGuard],
    realizations: list[HostRealization],
    proofs: set[str],
    binder_ids: list[str],
    *,
    param_index_box: list[int],
    catalog: BinderCatalog,
) -> str:
    """Fallback for holes that are not enclosed by any matching binder.

    Real catalogs cover all hole positions; this path only fires for
    partial catalogs / debug fixtures and keeps :func:`apply_phi` total.
    """
    if node.ctx is SyntCtx.VALUE:
        expr = host_exprs.get(node.name)
        if expr is None:
            raise _PhiAbstainSignal(f"no_host_expr for hole {node.name!r}")
        if node.sem not in _SEM_TO_SETTER:
            raise _PhiAbstainSignal(f"hole {node.name!r}: ctx VALUE sem {node.sem.value!r} not supported")
        short, api = _SEM_TO_SETTER[node.sem]
        if api not in catalog.parameterizing_apis:
            # The defensive map only applies when JDBC APIs are declared.
            raise _PhiAbstainSignal(
                f"value-hole {node.name!r}: defaulted api {api!r} not in catalog"
            )
        if node.card is Cardinality.MANY_BOUNDED:
            setters.append(SetterCall(
                param_index=-1, api=api, short_method=short,
                host_expr=expr, hole_name=node.name,
            ))
            realizations.append(HostRealization(
                hole_name=node.name, via="parameterized-api", api=api,
            ))
            proofs.add("Lemma 1 (Parameter inertness), induction step (lists).")
            return f"__INLIST_{node.name}__"
        setters.append(SetterCall(
            param_index=param_index_box[0], api=api, short_method=short,
            host_expr=expr, hole_name=node.name,
        ))
        realizations.append(HostRealization(
            hole_name=node.name, via="parameterized-api", api=api,
        ))
        param_index_box[0] += 1
        proofs.add("Lemma 1 (Parameter inertness).")
        binder_ids.append("sql-eq-value")
        return "?"
    if node.ctx is SyntCtx.IDENTIFIER:
        allow_const = allowlists.get(node.name)
        if not allow_const:
            raise _PhiAbstainSignal(f"identifier hole {node.name!r} has no allow-list")
        guards.append(AllowlistGuard(
            hole_name=node.name,
            host_expr=host_exprs.get(node.name, ""),
            allowlist_java_const=allow_const,
        ))
        realizations.append(HostRealization(
            hole_name=node.name, via="allowlist-lookup", api=None,
        ))
        proofs.add("Lemma 2 (Identifier allow-list closure).")
        binder_ids.append("sql-orderby-ident")
        return f"{{__GUARD_{node.name}__}}"
    raise _PhiAbstainSignal(f"hole {node.name!r}: ctx {node.ctx.value!r} not supported")


def _render_bare_hole_unreachable(_: Hole) -> str:  # pragma: no cover
    return ""


# --- helpers ------------------------------------------------------------------


def _render_sig(node: SIGNode, render) -> str:
    k = node.kind
    if k == "Select":
        parts = [render(c) for c in node.children]
        return "SELECT " + parts[0] + " FROM " + parts[1] + _join_tail(parts[2:])
    if k == "Insert":
        table, cols, vals = node.children
        return ("INSERT INTO " + render(table) + " ("
                + ", ".join(render(c) for c in cols.children) + ") VALUES ("
                + ", ".join(render(c) for c in vals.children) + ")")
    if k == "Update":
        head = "UPDATE " + render(node.children[0])
        sets = ", ".join(render(c) for c in node.children[1].children)
        out = head + " SET " + sets
        for ch in node.children[2:]:
            out += " " + render(ch)
        return out
    if k == "Delete":
        out = "DELETE FROM " + render(node.children[0])
        for ch in node.children[1:]:
            out += " " + render(ch)
        return out
    if k == "Projection":
        return ", ".join(render(c) for c in node.children)
    if k == "Column":
        return render(node.children[0])
    if k == "TableRef":
        return render(node.children[0])
    if k == "Where":
        return "WHERE " + render(node.children[0])
    if k == "Predicate":
        return " AND ".join(render(c) for c in node.children)
    if k == "Comparison":
        col, op, val = node.children
        return f"{render(col)} {render(op)} {render(val)}"
    if k == "LikeExpr":
        col, _kw, val = node.children
        return f"{render(col)} LIKE {render(val)}"
    if k == "InExpr":
        col = node.children[0]
        vals = node.children[2:]
        return f"{render(col)} IN (" + ", ".join(render(v) for v in vals) + ")"
    if k == "Assign":
        col, _eq, val = node.children
        return f"{render(col)} = {render(val)}"
    if k == "OrderList":
        return "ORDER BY " + ", ".join(render(c) for c in node.children)
    if k == "OrderItem":
        col, direction = node.children
        return f"{render(col)} {render(direction)}"
    if k == "LimitOffset":
        return " ".join(render(c) for c in node.children)
    if k == "Limit":
        return "LIMIT " + render(node.children[0])
    if k == "Offset":
        return "OFFSET " + render(node.children[0])
    # fallback: render children joined by spaces
    return " ".join(render(c) for c in node.children)


def _join_tail(parts: list[str]) -> str:
    return ("" if not parts else " " + " ".join(p for p in parts if p))


# --- IAM builder (convenience) ------------------------------------------------


def build_iam_from_lift(lift, host_exprs: dict[str, str],
                       symbols: tuple[SymbolEntry, ...] = ()) -> IAM:
    """Construct an IAM container from a Stage-D ``SIGLift`` and host exprs.

    The constraints set is currently empty in the MVP; future phases
    will populate it from stage-C's symbolic analysis.
    """
    return IAM(
        sig=lift.sig,
        holes=tuple(lift.holes),
        constraints=(),
        symbols=symbols,
        interpreter="sql",
    )
