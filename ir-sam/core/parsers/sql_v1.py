"""Stage D v1 — sqlglot-backed SQL parser (multi-dialect).

Opt-in alternative to the SQL₀ parser in :mod:`core.parsers`. Promotes the
recognized fragment to include JOINs, GROUP BY, HAVING, CTEs and subqueries
across PostgreSQL / MySQL / Oracle / SQLite / TSQL dialects.

Marker preservation
-------------------
``ParameterizedTemplate`` carries hole markers of the form ``<<H{i}>>``.
sqlglot cannot parse these directly, so we substitute each occurrence with a
unique bare identifier ``__IRSAM_HOLE_{i}__`` *before* parsing and recover
the hole on the SIG side by detecting the sentinel inside
:class:`sqlglot.expressions.Identifier` / :class:`Column` nodes. The
sentinel grammar is regular (``r"__IRSAM_HOLE_(\\d+)__"``); collisions with
user identifiers are vanishingly unlikely and would be caught by the
soundness gate downstream (any catalog-driven binder will refuse to bind
identifier-context holes without an allowlist).

Output is the same :class:`SIGLift` shape as the SQL₀ parser so the rest of
stages E–G stay untouched.

Dispatch
--------
Calling code can opt in by setting ``IRSAM_SQL_PARSER=v1`` (or by passing
``parser="v1"`` to :func:`parse_template_to_sig`). Default behavior remains
SQL₀.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

import sqlglot
import sqlglot.expressions as sgexp
from sqlglot.errors import ParseError

from core.iam import Cardinality, Hole, Literal, SIGNode, SemType, SyntCtx
from core.parsers import (
    SIGLift,
    SQL0AmbiguousIntent,
    SQL0SyntaxError,
    _collect_holes,
    _to_semtype,
)
from core.recon import ParameterizedTemplate


SUPPORTED_DIALECTS = (
    "postgres", "mysql", "oracle", "sqlite", "tsql", "snowflake", "bigquery",
)


_HOLE_MARKER_RE = re.compile(r"<<H(\d+)>>")
_HOLE_SENTINEL_RE = re.compile(r"__IRSAM_HOLE_(\d+)__")


def _substitute_markers(text: str) -> str:
    return _HOLE_MARKER_RE.sub(
        lambda m: f"__IRSAM_HOLE_{m.group(1)}__", text
    )


def _hole_index(name: str) -> int | None:
    m = _HOLE_SENTINEL_RE.fullmatch(name)
    return int(m.group(1)) if m else None


def _is_hole_identifier(node) -> int | None:
    """If ``node`` is an Identifier or Column wrapping a hole sentinel,
    return its index; otherwise ``None``."""
    if isinstance(node, sgexp.Identifier):
        return _hole_index(str(node.name))
    if isinstance(node, sgexp.Column):
        # Bare reference: ``Column(this=Identifier(__IRSAM_HOLE_n__))``,
        # no table qualifier.
        if node.table:
            return None
        inner = node.this
        if isinstance(inner, sgexp.Identifier):
            return _hole_index(str(inner.name))
    return None


# ---------------------------------------------------------------------------
# Lift sqlglot AST → SIG
# ---------------------------------------------------------------------------


class _V1Lifter:

    def __init__(self, holes: dict[int, object], hints: dict[str, str]):
        self.template_holes = holes  # idx → TemplateHole
        self.disambig_hints = hints

    # Entry points -----------------------------------------------------

    def lift(self, expr) -> SIGNode:
        # A WITH ... SELECT ... is reported by sqlglot as a Select whose
        # ``with`` arg holds the CTEs. Promote to WithQuery wrapper.
        if isinstance(expr, sgexp.Select):
            with_node = expr.args.get("with")
            if with_node is not None and with_node.expressions:
                ctes = []
                for cte in with_node.expressions:
                    if not isinstance(cte, sgexp.CTE):
                        continue
                    alias = cte.alias_or_name
                    if alias and _hole_index(alias) is not None:
                        raise SQL0AmbiguousIntent(
                            "CTE alias must be a static identifier"
                        )
                    ctes.append(SIGNode(
                        "Cte", (Literal(alias or ""), self.lift(cte.this)),
                    ))
                # Re-lift the SELECT without the WITH chain.
                inner = expr.copy()
                inner.set("with", None)
                return SIGNode("WithQuery",
                               tuple(ctes) + (self._select(inner),))
            return self._select(expr)
        if isinstance(expr, sgexp.Insert):
            return self._insert(expr)
        if isinstance(expr, sgexp.Update):
            return self._update(expr)
        if isinstance(expr, sgexp.Delete):
            return self._delete(expr)
        if isinstance(expr, sgexp.With):
            # CTE: SIG node wraps the inner query.
            ctes = []
            for cte in expr.expressions:
                if not isinstance(cte, sgexp.CTE):
                    continue
                alias = cte.alias_or_name
                if alias and _hole_index(alias) is not None:
                    raise SQL0AmbiguousIntent(
                        "CTE alias must be a static identifier"
                    )
                ctes.append(SIGNode(
                    "Cte", (Literal(alias or ""), self.lift(cte.this)),
                ))
            inner = expr.this
            if inner is None:
                raise SQL0SyntaxError("WITH without trailing query")
            return SIGNode("WithQuery", tuple(ctes) + (self.lift(inner),))
        raise SQL0SyntaxError(
            f"unsupported top-level node: {type(expr).__name__}"
        )

    # SELECT -----------------------------------------------------------

    def _select(self, sel: sgexp.Select) -> SIGNode:
        children: list = []
        children.append(self._projection(sel.expressions))
        frm = sel.args.get("from")
        if frm is not None and isinstance(frm, sgexp.From):
            children.append(self._table_ref(frm.this))
        joins = sel.args.get("joins") or []
        for j in joins:
            children.append(self._join(j))
        where = sel.args.get("where")
        if where is not None:
            children.append(SIGNode("Where", (self._predicate(where.this),)))
        group = sel.args.get("group")
        if group is not None:
            children.append(self._group(group))
        having = sel.args.get("having")
        if having is not None:
            children.append(SIGNode("Having", (self._predicate(having.this),)))
        order = sel.args.get("order")
        if order is not None:
            children.append(self._order(order))
        limit = sel.args.get("limit")
        if limit is not None:
            children.append(self._limit_offset(limit, sel.args.get("offset")))
        return SIGNode("Select", tuple(children))

    def _projection(self, expressions) -> SIGNode:
        items: list = []
        for e in expressions or []:
            if isinstance(e, sgexp.Star):
                items.append(Literal("*"))
                continue
            if isinstance(e, sgexp.Alias):
                inner = self._column_or_value(e.this, ident_only=False)
                items.append(SIGNode("AliasedColumn",
                                     (inner, Literal(e.alias_or_name))))
                continue
            items.append(self._column_or_value(e, ident_only=False))
        return SIGNode("Projection", tuple(items))

    def _table_ref(self, node) -> SIGNode:
        if isinstance(node, sgexp.Table):
            ident = node.this
            idx = _is_hole_identifier(ident)
            if idx is not None:
                raise SQL0AmbiguousIntent(
                    "hole in table-name position is not bindable; abstain"
                )
            alias = node.alias_or_name if node.alias else ""
            db = str(node.db) if node.db else ""
            qualifier = f"{db}." if db else ""
            name = qualifier + str(ident.name)
            if alias and alias != ident.name:
                return SIGNode("TableRef",
                               (Literal(name), Literal(alias)))
            return SIGNode("TableRef", (Literal(name),))
        if isinstance(node, sgexp.Subquery):
            inner = self.lift(node.this)
            alias = node.alias_or_name or ""
            return SIGNode("Subquery", (inner, Literal(alias)))
        raise SQL0SyntaxError(
            f"unsupported FROM node: {type(node).__name__}"
        )

    def _join(self, j: sgexp.Join) -> SIGNode:
        kind_parts: list[str] = []
        if j.side:
            kind_parts.append(str(j.side).upper())
        if j.kind:
            kind_parts.append(str(j.kind).upper())
        kind = " ".join(kind_parts).strip() or "INNER"
        tab = self._table_ref(j.this)
        on = j.args.get("on")
        if on is None:
            return SIGNode("Join", (Literal(kind), tab))
        return SIGNode("Join",
                       (Literal(kind), tab,
                        SIGNode("On", (self._predicate(on),))))

    def _group(self, group: sgexp.Group) -> SIGNode:
        items: list = []
        for e in group.expressions or []:
            idx = _is_hole_identifier(e)
            if idx is not None:
                items.append(self._make_hole(idx, ident=True))
            else:
                items.append(self._column_or_value(e, ident_only=True))
        return SIGNode("GroupBy", tuple(items))

    def _order(self, order: sgexp.Order) -> SIGNode:
        items: list = []
        for ord_node in order.expressions or []:
            if isinstance(ord_node, sgexp.Ordered):
                direction = "DESC" if ord_node.args.get("desc") else "ASC"
                inner = ord_node.this
            else:
                direction = "ASC"
                inner = ord_node
            idx = _is_hole_identifier(inner)
            if idx is not None:
                items.append(SIGNode("OrderItem",
                                     (self._make_hole(idx, ident=True),
                                      Literal(direction))))
            else:
                items.append(SIGNode("OrderItem",
                                     (self._column_or_value(inner,
                                                            ident_only=True),
                                      Literal(direction))))
        return SIGNode("OrderList", tuple(items))

    def _limit_offset(self, limit, offset) -> SIGNode:
        children: list = []
        lim_expr = limit.expression if isinstance(limit, sgexp.Limit) else limit
        children.append(SIGNode("Limit",
                                (self._value(lim_expr, force_int=True),)))
        if offset is not None:
            off_expr = (offset.expression
                        if isinstance(offset, sgexp.Offset) else offset)
            children.append(SIGNode("Offset",
                                    (self._value(off_expr, force_int=True),)))
        return SIGNode("LimitOffset", tuple(children))

    # INSERT/UPDATE/DELETE --------------------------------------------

    def _insert(self, ins: sgexp.Insert) -> SIGNode:
        tab_node = ins.this
        cols_node = None
        if isinstance(tab_node, sgexp.Schema):
            cols_node = tab_node.expressions
            tab_node = tab_node.this
        tab = self._table_ref(tab_node)
        cols: list = []
        for c in cols_node or []:
            cols.append(self._column_or_value(c, ident_only=True))
        # VALUES
        values_node = ins.expression
        if not isinstance(values_node, sgexp.Values):
            raise SQL0SyntaxError(
                f"INSERT without VALUES: {type(values_node).__name__}"
            )
        rows: list = []
        for tup in values_node.expressions:
            if isinstance(tup, sgexp.Tuple):
                vs = tuple(self._value(v) for v in tup.expressions)
            else:
                vs = (self._value(tup),)
            rows.append(SIGNode("ValueList", vs))
        if len(rows) == 1:
            return SIGNode("Insert",
                           (tab, SIGNode("ColumnList", tuple(cols)), rows[0]))
        return SIGNode("Insert",
                       (tab, SIGNode("ColumnList", tuple(cols)),
                        SIGNode("Rows", tuple(rows))))

    def _update(self, upd: sgexp.Update) -> SIGNode:
        tab = self._table_ref(upd.this)
        assigns: list = []
        for e in upd.expressions:
            if isinstance(e, sgexp.EQ):
                col = self._column_or_value(e.this, ident_only=True)
                val = self._value(e.expression)
                assigns.append(SIGNode("Assign", (col, Literal("="), val)))
        children: list = [tab, SIGNode("SetList", tuple(assigns))]
        where = upd.args.get("where")
        if where is not None:
            children.append(SIGNode("Where",
                                    (self._predicate(where.this),)))
        return SIGNode("Update", tuple(children))

    def _delete(self, dl: sgexp.Delete) -> SIGNode:
        tab = self._table_ref(dl.this)
        children: list = [tab]
        where = dl.args.get("where")
        if where is not None:
            children.append(SIGNode("Where",
                                    (self._predicate(where.this),)))
        return SIGNode("Delete", tuple(children))

    # Predicate / atom -------------------------------------------------

    def _predicate(self, node) -> SIGNode:
        atoms = list(self._flatten_and(node))
        return SIGNode("Predicate", tuple(self._atom(a) for a in atoms))

    def _flatten_and(self, node):
        if isinstance(node, sgexp.And):
            yield from self._flatten_and(node.this)
            yield from self._flatten_and(node.expression)
        else:
            yield node

    def _atom(self, node) -> SIGNode:
        op_map = {
            sgexp.EQ: "=", sgexp.NEQ: "!=", sgexp.LT: "<", sgexp.GT: ">",
            sgexp.LTE: "<=", sgexp.GTE: ">=",
        }
        for ty, sym in op_map.items():
            if isinstance(node, ty):
                col = self._column_or_value(node.this, ident_only=True)
                val = self._value(node.expression)
                return SIGNode("Comparison", (col, Literal(sym), val))
        if isinstance(node, sgexp.Like):
            col = self._column_or_value(node.this, ident_only=True)
            val = self._value(node.expression)
            return SIGNode("LikeExpr", (col, Literal("LIKE"), val))
        if isinstance(node, sgexp.In):
            col = self._column_or_value(node.this, ident_only=True)
            return self._in_atom(col, node)
        if isinstance(node, sgexp.Is):
            col = self._column_or_value(node.this, ident_only=True)
            return SIGNode("Is", (col, self._value(node.expression)))
        if isinstance(node, sgexp.Paren):
            return self._atom(node.this)
        if isinstance(node, sgexp.Or):
            # OR atoms: we keep them as a flat Or-disjunction; binder
            # treats this as a single Predicate atom.
            left = self._predicate(node.this)
            right = self._predicate(node.expression)
            return SIGNode("Or", (left, right))
        raise SQL0SyntaxError(
            f"unsupported predicate atom: {type(node).__name__}"
        )

    def _in_atom(self, col: SIGNode, node: sgexp.In) -> SIGNode:
        exprs = node.expressions or []
        if not exprs and node.args.get("query"):
            inner = self.lift(node.args["query"].this if isinstance(
                node.args["query"], sgexp.Subquery) else node.args["query"])
            return SIGNode("InSubquery", (col, Literal("IN"), inner))
        vals = [self._value(v) for v in exprs]
        holes_in_list = [v for v in vals if isinstance(v, Hole)]
        if len(vals) == 1 and len(holes_in_list) == 1:
            lone = holes_in_list[0]
            hint = self.disambig_hints.get(lone.name)
            if hint == "in_list_csv":
                promoted = Hole(
                    name=lone.name, ctx=lone.ctx, sem=lone.sem,
                    card=Cardinality.MANY_BOUNDED, allowlist=lone.allowlist,
                )
                return SIGNode("InExpr", (col, Literal("IN"), promoted))
            if hint == "string_value":
                return SIGNode("InExpr", (col, Literal("IN"), lone))
            raise SQL0AmbiguousIntent(
                "IN-list with a single attacker-controlled hole is "
                "ambiguous; pipeline must call the Stage-D disambiguator "
                "with the 'sql/in_position' label set.")
        return SIGNode("InExpr", (col, Literal("IN"), *tuple(vals)))

    # Column / value ---------------------------------------------------

    def _column_or_value(self, node, *, ident_only: bool):
        if isinstance(node, sgexp.Column):
            idx = _is_hole_identifier(node)
            if idx is not None:
                if ident_only:
                    raise SQL0AmbiguousIntent(
                        "hole in projection/column-name position is not "
                        "bindable; abstain"
                    )
                # Value-context bare hole (e.g., WHERE x = <<H0>>): becomes
                # a value hole.
                return self._make_hole(idx, ident=False)
            tab = node.table
            col = str(node.name)
            if tab:
                return SIGNode("Column", (Literal(f"{tab}.{col}"),))
            return SIGNode("Column", (Literal(col),))
        if isinstance(node, sgexp.Identifier):
            idx = _hole_index(str(node.name))
            if idx is not None:
                if ident_only:
                    return self._make_hole(idx, ident=True)
                return self._make_hole(idx, ident=False)
            return SIGNode("Column", (Literal(str(node.name)),))
        if isinstance(node, sgexp.Dot):
            return SIGNode("Column", (Literal(node.sql()),))
        if isinstance(node, sgexp.Star):
            return Literal("*")
        if isinstance(node, (sgexp.Literal, sgexp.Boolean, sgexp.Null)):
            return self._value(node)
        if isinstance(node, sgexp.Func):
            # Aggregates / function calls in projection or GROUP BY.
            args = tuple(self._column_or_value(a, ident_only=False)
                         for a in (node.args.get("expressions") or
                                   ([node.this] if node.this is not None else [])))
            return SIGNode("FuncCall",
                           (Literal(type(node).__name__.upper()),) + args)
        raise SQL0SyntaxError(
            f"unsupported column-or-value: {type(node).__name__}"
        )

    def _value(self, node, *, force_int: bool = False):
        if node is None:
            raise SQL0SyntaxError("expected value, got None")
        # Hole?
        idx = _is_hole_identifier(node)
        if idx is not None:
            return self._make_hole(idx, ident=False,
                                   force_sem=SemType.INTEGER if force_int else None)
        if isinstance(node, sgexp.Literal):
            return Literal(str(node.this))
        if isinstance(node, sgexp.Boolean):
            return Literal("TRUE" if node.this else "FALSE")
        if isinstance(node, sgexp.Null):
            return Literal("NULL")
        if isinstance(node, sgexp.Neg):
            # ``-1`` etc.
            inner = node.this
            if isinstance(inner, sgexp.Literal):
                return Literal(f"-{inner.this}")
        if isinstance(node, sgexp.Paren):
            return self._value(node.this, force_int=force_int)
        # Allow column references on RHS (e.g., JOIN ON u.id = o.uid).
        if isinstance(node, sgexp.Column):
            return self._column_or_value(node, ident_only=False)
        if isinstance(node, sgexp.Func):
            return self._column_or_value(node, ident_only=False)
        raise SQL0SyntaxError(
            f"unsupported value: {type(node).__name__}"
        )

    def _make_hole(self, idx: int, *, ident: bool,
                   force_sem: SemType | None = None) -> Hole:
        th = self.template_holes.get(idx)
        if th is None:
            raise SQL0SyntaxError(f"unknown hole index {idx}")
        sem = force_sem if force_sem is not None else _to_semtype(th.sem)
        ctx = SyntCtx.IDENTIFIER if ident else SyntCtx.VALUE
        if ident:
            sem = SemType.ENUM
        return Hole(name=f"h{idx}", ctx=ctx, sem=sem)


# ---------------------------------------------------------------------------
# Public entry
# ---------------------------------------------------------------------------


def parse_template_to_sig_v1(
    template: ParameterizedTemplate,
    dialect: str = "postgres",
    disambig_hints: dict[str, str] | None = None,
) -> SIGLift:
    """Lift ``template`` to a SIG using sqlglot.

    ``dialect`` must be one of :data:`SUPPORTED_DIALECTS`. Hole markers
    ``<<H{i}>>`` are recovered as :class:`Hole` leaves with ``ctx`` chosen
    by AST position (VALUE in WHERE/HAVING/Insert/Update; IDENTIFIER in
    GROUP BY / ORDER BY).

    Raises:
        SQL0SyntaxError: input doesn't parse under the dialect.
        SQL0AmbiguousIntent: a hole appears where the model cannot bind
            it soundly (table name, JOIN qualifier, CTE alias, …).
    """
    if dialect not in SUPPORTED_DIALECTS:
        raise SQL0SyntaxError(f"unsupported dialect: {dialect}")

    sentinel_text = _substitute_markers(template.text)
    try:
        tree = sqlglot.parse_one(sentinel_text, read=dialect)
    except ParseError as exc:
        raise SQL0SyntaxError(str(exc)[:200]) from exc
    if tree is None:
        raise SQL0SyntaxError("empty SQL input")

    holes_by_idx = {h.idx: h for h in template.holes}
    lifter = _V1Lifter(holes_by_idx, dict(disambig_hints or {}))
    sig = lifter.lift(tree)
    holes = tuple(_collect_holes(sig))
    return SIGLift(sig=sig, holes=holes)


# ---------------------------------------------------------------------------
# Dispatch helper
# ---------------------------------------------------------------------------


def select_parser() -> str:
    """Return ``'v1'`` if env opts in, else ``'sql0'``."""
    return os.environ.get("IRSAM_SQL_PARSER", "sql0").strip().lower()
