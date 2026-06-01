"""Stage D --- SQL_0 lexer, parser, and lift-to-SIG.

The SQL_0 fragment (cf. ``docs/soundness-proof.md``):

    SELECT proj FROM table [WHERE pred]
                          [ORDER BY ident [ASC|DESC]]
                          [LIMIT int [OFFSET int]]
    INSERT INTO table (cols) VALUES (vals)
    UPDATE table SET col = val (, col = val)* [WHERE pred]
    DELETE FROM table [WHERE pred]

    pred  ::= atom (AND atom)*
    atom  ::= col cmp val | col LIKE val | col IN '(' val (',' val)* ')'
    cmp   ::= '='|'!='|'<>'|'<'|'>'|'<='|'>='
    val   ::= int | str | <<H{n}>>
    col   ::= ident | <<H{n}>>          (* identifier-hole; only in ORDER BY *)

Holes appearing in a *value* position become SIG ``Hole`` nodes with
``ctx = SyntCtx.VALUE``; holes in an identifier position (only allowed
in ``ORDER BY``) become ``ctx = SyntCtx.IDENTIFIER``.

Holes appearing anywhere outside these positions (e.g. a hole as a
table name) raise :class:`SQL0AmbiguousIntent`, which the upstream
pipeline turns into abstention.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from core.iam import (
    Cardinality,
    Hole,
    Literal,
    SIGNode,
    SemType,
    SyntCtx,
)
from core.recon import ParameterizedTemplate, TemplateHole


class SQL0SyntaxError(ValueError):
    """Raised when the input does not parse under SQL_0."""


class SQL0AmbiguousIntent(ValueError):
    """Raised when a hole appears in a position the model cannot soundly bind.

    Examples: hole as table name, hole as JOIN clause, hole as operator.
    The pipeline turns this into a stage-D abstention.
    """


# --- lexer --------------------------------------------------------------------


_KEYWORDS = {
    "SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "ORDER", "BY", "ASC", "DESC",
    "LIMIT", "OFFSET", "INSERT", "INTO", "VALUES", "UPDATE", "SET",
    "DELETE", "LIKE", "IN", "IS", "NULL", "AS",
}


@dataclass(frozen=True)
class SQLTok:
    kind: str
    text: str
    pos: int


_SQL_TOKEN_RE = re.compile(
    r"""
    (?P<HOLE>    <<H\d+>> )
  | (?P<STRING>  ' (?:''|[^'])* ' )
  | (?P<NUMBER>  \d+(?:\.\d+)? )
  | (?P<IDENT>   [A-Za-z_][A-Za-z_0-9]* )
  | (?P<OP>      <=|>=|!=|<>|[=<>(),*.;] )
  | (?P<WS>      \s+ )
    """,
    re.VERBOSE,
)


def lex_sql0(src: str) -> list[SQLTok]:
    out: list[SQLTok] = []
    i = 0
    while i < len(src):
        m = _SQL_TOKEN_RE.match(src, i)
        if not m:
            raise SQL0SyntaxError(f"unexpected char {src[i]!r} at {i}")
        kind = m.lastgroup or "?"
        text = m.group()
        if kind == "WS":
            i = m.end()
            continue
        if kind == "IDENT" and text.upper() in _KEYWORDS:
            kind = text.upper()
            text = text.upper()
        out.append(SQLTok(kind=kind, text=text, pos=m.start()))
        i = m.end()
    return out


# --- parser -------------------------------------------------------------------


@dataclass
class _Parser:
    toks: list[SQLTok]
    holes: dict[int, TemplateHole]
    pos: int = 0
    # Optional disambiguation hints: hole-name (e.g. "h0") -> label string.
    # Populated by the upstream pipeline after a Stage-D disambiguator call.
    # Keys missing from the map are interpreted as "no hint" (preserve the
    # original abstention behavior).
    disambig_hints: dict[str, str] = field(default_factory=dict)

    # --- helpers ---
    def peek(self, off: int = 0) -> SQLTok | None:
        if self.pos + off >= len(self.toks):
            return None
        return self.toks[self.pos + off]

    def consume(self, kind_or_text: str) -> SQLTok:
        t = self.peek()
        if t is None or (t.kind != kind_or_text and t.text != kind_or_text):
            raise SQL0SyntaxError(
                f"expected {kind_or_text!r} got {t.kind if t else 'EOF'} {t.text if t else ''}"
            )
        self.pos += 1
        return t

    def maybe(self, *kinds: str) -> SQLTok | None:
        t = self.peek()
        if t and (t.kind in kinds or t.text in kinds):
            self.pos += 1
            return t
        return None

    def eof(self) -> bool:
        t = self.peek()
        return t is None or (t.kind == ";" and self.pos == len(self.toks) - 1)

    # --- productions ---
    def parse_query(self) -> SIGNode:
        t = self.peek()
        if t is None:
            raise SQL0SyntaxError("empty query")
        if t.kind == "SELECT":
            return self.parse_select()
        if t.kind == "INSERT":
            return self.parse_insert()
        if t.kind == "UPDATE":
            return self.parse_update()
        if t.kind == "DELETE":
            return self.parse_delete()
        raise SQL0SyntaxError(f"unexpected start token {t.text!r}")

    # SELECT ---
    def parse_select(self) -> SIGNode:
        self.consume("SELECT")
        proj = self.parse_projection()
        self.consume("FROM")
        table = self.parse_table_ref()
        children: list = [proj, table]
        if self.maybe("WHERE"):
            children.append(SIGNode("Where", (self.parse_predicate(),)))
        if self.maybe("ORDER"):
            self.consume("BY")
            children.append(self.parse_order_list())
        if self.maybe("LIMIT"):
            children.append(self.parse_limit_offset())
        return SIGNode("Select", tuple(children))

    def parse_projection(self) -> SIGNode:
        if self.maybe("*"):
            return SIGNode("Projection", (Literal("*"),))
        cols: list = [self.parse_column()]
        while self.maybe(","):
            cols.append(self.parse_column())
        return SIGNode("Projection", tuple(cols))

    def parse_table_ref(self) -> SIGNode:
        t = self.peek()
        if t is None:
            raise SQL0SyntaxError("expected table reference, got EOF")
        if t.kind == "HOLE":
            raise SQL0AmbiguousIntent(
                "hole in table-name position is not bindable; abstain"
            )
        ident = self.consume("IDENT")
        return SIGNode("TableRef", (Literal(ident.text),))

    def parse_column(self) -> SIGNode:
        # identifier or `t.c`
        t = self.peek()
        if t is None:
            raise SQL0SyntaxError("expected column, got EOF")
        if t.kind == "HOLE":
            raise SQL0AmbiguousIntent(
                "hole in projection/column-name position is not bindable; abstain"
            )
        ident = self.consume("IDENT")
        if self.maybe("."):
            ident2 = self.consume("IDENT")
            return SIGNode("Column", (Literal(f"{ident.text}.{ident2.text}"),))
        return SIGNode("Column", (Literal(ident.text),))

    # Predicate ---
    def parse_predicate(self) -> SIGNode:
        atoms: list = [self.parse_atom()]
        while self.maybe("AND"):
            atoms.append(self.parse_atom())
        return SIGNode("Predicate", tuple(atoms))

    def parse_atom(self) -> SIGNode:
        col = self.parse_column()
        t = self.peek()
        if t is None:
            raise SQL0SyntaxError("expected operator after column")
        if t.text in ("=", "<", ">", "<=", ">=", "!=", "<>"):
            op = t.text
            self.pos += 1
            val = self.parse_value("p")
            return SIGNode("Comparison", (col, Literal(op), val))
        if t.kind == "LIKE":
            self.pos += 1
            val = self.parse_value("p")
            return SIGNode("LikeExpr", (col, Literal("LIKE"), val))
        if t.kind == "IN":
            self.pos += 1
            self.consume("(")
            vals: list = [self.parse_value("p")]
            while self.maybe(","):
                vals.append(self.parse_value("p"))
            self.consume(")")
            # Determine cardinality:
            #   * all literals -> bounded (no hole)
            #   * literal list mixed with holes -> bounded
            #   * single hole IN  (?, ?, ?, ...) is represented as one hole
            #     with cardinality MANY_BOUNDED (binder expands placeholders)
            holes_in_list = [v for v in vals if isinstance(v, Hole)]
            if len(vals) == 1 and len(holes_in_list) == 1:
                # Single attacker-controlled CSV inside IN(...) is
                # ambiguous in SQL_0: we cannot decide arity statically.
                # If the upstream pipeline ran the Stage-D disambiguator
                # and supplied a hint, we honor it; otherwise we abstain.
                lone = holes_in_list[0]
                hint = self.disambig_hints.get(lone.name)
                if hint == "in_list_csv":
                    # Promote the hole to MANY_BOUNDED so the binder
                    # (sql-in-list rule) emits the placeholder loop.
                    promoted = Hole(
                        name=lone.name,
                        ctx=lone.ctx,
                        sem=lone.sem,
                        card=Cardinality.MANY_BOUNDED,
                        allowlist=lone.allowlist,
                    )
                    return SIGNode(
                        "InExpr",
                        (col, Literal("IN"), promoted),
                    )
                if hint == "string_value":
                    # Treat as a single-string IN-list; the binder will
                    # emit IN (?) with one placeholder.
                    return SIGNode(
                        "InExpr",
                        (col, Literal("IN"), lone),
                    )
                # No hint or unrecognized hint -> abstain (default).
                raise SQL0AmbiguousIntent(
                    "IN-list with a single attacker-controlled hole is "
                    "ambiguous; pipeline must call the Stage-D "
                    "disambiguator with the 'sql/in_position' label set.")
            return SIGNode("InExpr", (col, Literal("IN"), *tuple(vals)))
        raise SQL0SyntaxError(f"unsupported operator {t.text!r}")

    # Value / Hole ---
    def parse_value(self, hint: str) -> SIGNode | Hole | Literal:
        t = self.peek()
        if t is None:
            raise SQL0SyntaxError("expected value, got EOF")
        if t.kind == "HOLE":
            self.pos += 1
            idx = int(re.match(r"<<H(\d+)>>", t.text).group(1))  # type: ignore[union-attr]
            th = self.holes[idx]
            sem = _to_semtype(th.sem)
            return Hole(name=f"h{idx}", ctx=SyntCtx.VALUE, sem=sem)
        if t.kind == "STRING":
            self.pos += 1
            return Literal(t.text)
        if t.kind == "NUMBER":
            self.pos += 1
            return Literal(t.text)
        if t.kind == "IDENT" and t.text.upper() == "NULL":
            self.pos += 1
            return Literal("NULL")
        raise SQL0SyntaxError(f"expected value, got {t.text!r}")

    # ORDER BY ---
    def parse_order_list(self) -> SIGNode:
        items: list = [self.parse_order_item()]
        while self.maybe(","):
            items.append(self.parse_order_item())
        return SIGNode("OrderList", tuple(items))

    def parse_order_item(self) -> SIGNode | Hole:
        t = self.peek()
        if t is None:
            raise SQL0SyntaxError("expected column in ORDER BY, got EOF")
        if t.kind == "HOLE":
            self.pos += 1
            idx = int(re.match(r"<<H(\d+)>>", t.text).group(1))  # type: ignore[union-attr]
            _th = self.holes[idx]
            # ORDER BY positions may be qualified by ASC/DESC
            direction = "ASC"
            if self.maybe("ASC"):
                direction = "ASC"
            elif self.maybe("DESC"):
                direction = "DESC"
            return SIGNode("OrderItem",
                           (Hole(name=f"h{idx}", ctx=SyntCtx.IDENTIFIER,
                                 sem=SemType.ENUM),
                            Literal(direction)))
        col = self.parse_column()
        direction = "ASC"
        if self.maybe("ASC"):
            direction = "ASC"
        elif self.maybe("DESC"):
            direction = "DESC"
        return SIGNode("OrderItem", (col, Literal(direction)))

    # LIMIT/OFFSET ---
    def parse_limit_offset(self) -> SIGNode:
        children: list = []
        v = self.parse_value("lim")
        if isinstance(v, Hole):
            v = Hole(name=v.name, ctx=SyntCtx.VALUE, sem=SemType.INTEGER)
        children.append(SIGNode("Limit", (v,)))
        if self.maybe("OFFSET"):
            v2 = self.parse_value("off")
            if isinstance(v2, Hole):
                v2 = Hole(name=v2.name, ctx=SyntCtx.VALUE, sem=SemType.INTEGER)
            children.append(SIGNode("Offset", (v2,)))
        return SIGNode("LimitOffset", tuple(children))

    # INSERT/UPDATE/DELETE ---
    def parse_insert(self) -> SIGNode:
        self.consume("INSERT")
        self.consume("INTO")
        table = self.parse_table_ref()
        self.consume("(")
        cols: list = [self.parse_column()]
        while self.maybe(","):
            cols.append(self.parse_column())
        self.consume(")")
        self.consume("VALUES")
        self.consume("(")
        vals: list = [self.parse_value("p")]
        while self.maybe(","):
            vals.append(self.parse_value("p"))
        self.consume(")")
        return SIGNode("Insert",
                       (table, SIGNode("ColumnList", tuple(cols)),
                        SIGNode("ValueList", tuple(vals))))

    def parse_update(self) -> SIGNode:
        self.consume("UPDATE")
        table = self.parse_table_ref()
        self.consume("SET")
        assigns: list = [self._parse_assign()]
        while self.maybe(","):
            assigns.append(self._parse_assign())
        children = [table, SIGNode("SetList", tuple(assigns))]
        if self.maybe("WHERE"):
            children.append(SIGNode("Where", (self.parse_predicate(),)))
        return SIGNode("Update", tuple(children))

    def _parse_assign(self) -> SIGNode:
        col = self.parse_column()
        self.consume("=")
        val = self.parse_value("p")
        return SIGNode("Assign", (col, Literal("="), val))

    def parse_delete(self) -> SIGNode:
        self.consume("DELETE")
        self.consume("FROM")
        table = self.parse_table_ref()
        children = [table]
        if self.maybe("WHERE"):
            children.append(SIGNode("Where", (self.parse_predicate(),)))
        return SIGNode("Delete", tuple(children))


def _to_semtype(s: str) -> SemType:
    return {
        "string": SemType.STRING,
        "integer": SemType.INTEGER,
        "decimal": SemType.DECIMAL,
        "boolean": SemType.BOOLEAN,
        "date": SemType.DATE,
        "blob": SemType.BLOB,
    }.get(s, SemType.STRING)


# --- public lift ---


@dataclass(frozen=True)
class SIGLift:
    sig: SIGNode
    holes: tuple[Hole, ...]


def parse_template_to_sig(
    template: ParameterizedTemplate,
    disambig_hints: dict[str, str] | None = None,
    *,
    parser: str | None = None,
    dialect: str = "postgres",
) -> SIGLift:
    """Lift a parameterized template into a SIG and the ordered hole list.

    The hole list is built by walking the SIG and collecting every
    :class:`~core.iam.Hole` leaf in textual (left-to-right) order.

    ``disambig_hints`` (optional) maps a hole name (``"h0"``, ``"h1"``,
    ...) to a label string from
    :mod:`core.disambig.labels`. The pipeline populates this map by
    calling the Stage-D disambiguator on an :class:`SQL0AmbiguousIntent`
    point and re-invoking this function. With ``None`` (default) the
    parser preserves its original abstain-on-ambiguity behavior.

    ``parser`` selects the Stage-D implementation:

    * ``"v1"``   — sqlglot-backed parser supporting JOIN / GROUP BY /
      HAVING / CTE / subquery across :data:`core.parsers.sql_v1.SUPPORTED_DIALECTS`
      (default).
    * ``"sql0"`` — original minimal LL parser (see module docstring).

    Falls through to the ``IRSAM_SQL_PARSER`` env var when ``parser`` is
    ``None``.
    """
    if parser is None:
        import os
        parser = os.environ.get("IRSAM_SQL_PARSER", "v1").strip().lower()
    if parser == "v1":
        from core.parsers.sql_v1 import parse_template_to_sig_v1
        return parse_template_to_sig_v1(
            template, dialect=dialect, disambig_hints=disambig_hints,
        )
    return _parse_template_to_sig_sql0(
        template, disambig_hints=disambig_hints,
    )


def _parse_template_to_sig_sql0(
    template: ParameterizedTemplate,
    disambig_hints: dict[str, str] | None = None,
) -> SIGLift:
    hole_by_idx = {h.idx: h for h in template.holes}
    toks = lex_sql0(template.text)
    if not toks:
        raise SQL0SyntaxError("empty SQL_0 input")
    p = _Parser(
        toks=toks,
        holes=hole_by_idx,
        disambig_hints=dict(disambig_hints or {}),
    )
    sig = p.parse_query()
    # consume optional trailing semicolon
    p.maybe(";")
    if p.peek() is not None:
        raise SQL0SyntaxError(f"trailing tokens at position {p.pos}")
    holes = tuple(_collect_holes(sig))
    return SIGLift(sig=sig, holes=holes)


def _collect_holes(node: object) -> list[Hole]:
    out: list[Hole] = []
    if isinstance(node, Hole):
        return [node]
    if isinstance(node, SIGNode):
        for ch in node.children:
            out.extend(_collect_holes(ch))
    return out
