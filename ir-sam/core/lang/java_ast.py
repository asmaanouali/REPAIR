"""Java AST-driven slicer (Phase 2).

Tree-sitter-java replacement for the regex-based MVP slicer in
:mod:`core.slicer`. Selected at runtime via ``IRSAM_SLICER=ts``; the
default remains the regex slicer until a release gate ratifies the AST
path. Both implementations produce identical :class:`SliceResult` /
:class:`SliceAbstention` values for the shapes the regex slicer covers
and the AST slicer additionally handles tricky variants the regex tier
abstains on (ternary concat, parenthesized String.format, nested
StringBuilder reassignment).
"""

from __future__ import annotations

import re
from typing import Optional

from core.lang._treesitter import (
    TreeSitterUnavailable,
    node_text,
    parse_java,
)
from core.slicer import (
    SliceAbstention,
    SliceResult,
    StringPart,
    _java_type_to_sem,
)


# Sink APIs we recognize. Keep in sync with ``core.slicer._SINK_PATTERNS``.
_SINK_APIS: frozenset[str] = frozenset({
    "executeQuery", "executeUpdate", "execute", "addBatch",
    "prepareStatement", "prepareCall",
    "createStatement",
    "createQuery", "createNativeQuery", "createNamedQuery",
    "compile",
})


def _is_str_or_charseq(t: str) -> bool:
    return t in {"String", "StringBuilder", "StringBuffer", "CharSequence",
                 "java.lang.String"}


# ---------------------------------------------------------------------------
# find_sink_calls
# ---------------------------------------------------------------------------


def find_sink_calls(java_src: str) -> list[tuple[int, str, str, str]]:
    """AST counterpart of ``core.slicer.find_sink_calls``."""
    try:
        tree, src_bytes = parse_java(java_src)
    except TreeSitterUnavailable:
        from core.slicer import find_sink_calls as _regex
        return _regex(java_src)

    out: list[tuple[int, str, str, str]] = []
    _collect_sinks(tree.root_node, src_bytes, out)
    return out


def _collect_sinks(node, src_bytes: bytes, out: list) -> None:
    if node.type == "method_invocation":
        name_node = node.child_by_field_name("name")
        if name_node is not None:
            api = node_text(name_node, src_bytes)
            if api in _SINK_APIS:
                obj_node = node.child_by_field_name("object")
                recv = node_text(obj_node, src_bytes) if obj_node else ""
                call_text = node_text(node, src_bytes)
                line = node.start_point[0] + 1
                out.append((line, recv, api, call_text))
    for ch in node.children:
        _collect_sinks(ch, src_bytes, out)


# ---------------------------------------------------------------------------
# Local-variable environment
# ---------------------------------------------------------------------------


class _Env:
    """Local-variable environment for one method body.

    ``decls[name]`` stores ``(java_type, init_expr_node, decl_node)``.
    ``init_expr_node`` is the last RHS assigned (None if uninitialized).
    """

    __slots__ = ("decls", "src", "method_node")

    def __init__(self, src_bytes: bytes, method_node):
        self.decls: dict[str, tuple[str, Optional[object], Optional[object]]] = {}
        self.src = src_bytes
        self.method_node = method_node


def _build_env(method_node, src_bytes: bytes) -> _Env:
    env = _Env(src_bytes, method_node)
    _scan_parameters(method_node, env)
    body = method_node.child_by_field_name("body")
    if body is not None:
        _scan_statements(body, env)
    return env


def _scan_parameters(method_node, env: _Env) -> None:
    params = method_node.child_by_field_name("parameters")
    if params is None:
        return
    for ch in params.children:
        if ch.type != "formal_parameter":
            continue
        type_node = ch.child_by_field_name("type")
        name_node = ch.child_by_field_name("name")
        if type_node is None or name_node is None:
            continue
        jt = node_text(type_node, env.src)
        name = node_text(name_node, env.src)
        env.decls[name] = (jt, None, ch)


def _scan_statements(node, env: _Env) -> None:
    """Recursively scan a block for declarations / assignments / SB appends."""
    for ch in node.children:
        t = ch.type
        if t == "local_variable_declaration":
            _absorb_local_decl(ch, env)
        elif t == "expression_statement":
            inner = ch.named_child(0) if ch.named_child_count else None
            if inner is None:
                continue
            if inner.type == "assignment_expression":
                _absorb_assignment(inner, env)
            elif inner.type == "method_invocation":
                _absorb_sb_chain(inner, env)
        elif ch.type in ("block", "if_statement", "for_statement",
                         "while_statement", "try_statement", "catch_clause",
                         "finally_clause", "switch_statement", "switch_block",
                         "switch_block_statement_group"):
            _scan_statements(ch, env)


def _absorb_local_decl(decl_node, env: _Env) -> None:
    type_node = decl_node.child_by_field_name("type")
    jt = node_text(type_node, env.src) if type_node else "var"
    for declarator in decl_node.children:
        if declarator.type != "variable_declarator":
            continue
        name_node = declarator.child_by_field_name("name")
        val_node = declarator.child_by_field_name("value")
        if name_node is None:
            continue
        name = node_text(name_node, env.src)
        env.decls[name] = (jt, val_node, decl_node)


def _absorb_assignment(assign_node, env: _Env) -> None:
    left = assign_node.child_by_field_name("left")
    op_node = assign_node.child_by_field_name("operator")
    right = assign_node.child_by_field_name("right")
    if left is None or right is None or left.type != "identifier":
        return
    name = node_text(left, env.src)
    if name not in env.decls:
        return
    jt, prev, decl = env.decls[name]
    op = node_text(op_node, env.src) if op_node else "="
    if op == "=":
        # Detect self-reference (``sql = sql + …``) and fold into a
        # CONCAT sentinel so the previous binding survives the rewrite.
        if _references(right, name, env.src):
            env.decls[name] = (jt, ("SELFCONCAT", prev, right, name), decl)
        else:
            env.decls[name] = (jt, right, decl)
    elif op == "+=":
        env.decls[name] = (jt, ("CONCAT", prev, right), decl)


def _references(node, name: str, src_bytes: bytes) -> bool:
    if node is None:
        return False
    if node.type == "identifier" and node_text(node, src_bytes) == name:
        return True
    for ch in node.children:
        if _references(ch, name, src_bytes):
            return True
    return False


def _absorb_sb_chain(call_node, env: _Env) -> None:
    """Capture ``sb.append(...).append(...)`` chains for StringBuilder vars."""
    # Walk the receiver chain to find the root identifier.
    root_id = call_node
    while root_id.type == "method_invocation":
        obj = root_id.child_by_field_name("object")
        if obj is None:
            return
        root_id = obj
    if root_id.type != "identifier":
        return
    name = node_text(root_id, env.src)
    if name not in env.decls:
        return
    jt, prev, decl = env.decls[name]
    if jt not in ("StringBuilder", "StringBuffer", "java.lang.StringBuilder"):
        return
    # Collect each .append(arg) argument in textual order.
    appends: list = []
    cur = call_node
    chain: list = []
    while cur.type == "method_invocation":
        chain.append(cur)
        cur = cur.child_by_field_name("object")
        if cur is None:
            break
    for inv in reversed(chain):
        nm = inv.child_by_field_name("name")
        if nm is None or node_text(nm, env.src) != "append":
            continue
        args = inv.child_by_field_name("arguments")
        if args is None:
            continue
        for ach in args.children:
            if ach.is_named:
                appends.append(ach)
    if not appends:
        return
    new = prev
    for a in appends:
        new = ("CONCAT", new, a) if new is not None else a
    env.decls[name] = (jt, new, decl)


# ---------------------------------------------------------------------------
# Expression expansion
# ---------------------------------------------------------------------------


def _expand(node_or_tuple, env: _Env, depth: int = 0,
            self_subst: dict | None = None) -> tuple[StringPart, ...]:
    if depth > 32:
        return (StringPart.var("…"),)
    # Synthesized concat sentinel from `+=` and SB append fold.
    if isinstance(node_or_tuple, tuple) and node_or_tuple and node_or_tuple[0] == "CONCAT":
        _, lhs, rhs = node_or_tuple
        parts: list[StringPart] = []
        if lhs is not None:
            parts.extend(_expand(lhs, env, depth + 1, self_subst))
        if rhs is not None:
            parts.extend(_expand(rhs, env, depth + 1, self_subst))
        return tuple(_merge(parts))
    # Self-reassignment sentinel: ``x = x + Y`` → expand Y but substitute
    # each occurrence of ``x`` with the prior value of ``x``.
    if isinstance(node_or_tuple, tuple) and node_or_tuple and node_or_tuple[0] == "SELFCONCAT":
        _, prev, rhs_node, name = node_or_tuple
        subst = dict(self_subst or {})
        subst[name] = prev
        return _expand(rhs_node, env, depth + 1, subst)
    node = node_or_tuple
    if node is None:
        return ()

    t = node.type
    if t == "string_literal":
        return (StringPart.lit(_unquote(node_text(node, env.src))),)
    if t == "decimal_integer_literal" or t == "hex_integer_literal":
        return (StringPart.lit(node_text(node, env.src)),)
    if t == "character_literal":
        return (StringPart.lit(node_text(node, env.src).strip("'")),)
    if t == "binary_expression":
        op = node.child_by_field_name("operator")
        if op is not None and node_text(op, env.src) == "+":
            lhs = node.child_by_field_name("left")
            rhs = node.child_by_field_name("right")
            return tuple(_merge(
                list(_expand(lhs, env, depth + 1, self_subst))
                + list(_expand(rhs, env, depth + 1, self_subst))
            ))
        return (StringPart.var(node_text(node, env.src)),)
    if t == "parenthesized_expression":
        inner = node.named_child(0) if node.named_child_count else None
        return _expand(inner, env, depth + 1, self_subst)
    if t == "ternary_expression":
        # Conservative: a ternary on a string is a runtime choice — we
        # cannot statically commit to either branch. Treat as opaque var.
        return (StringPart.var(node_text(node, env.src)),)
    if t == "identifier":
        name = node_text(node, env.src)
        if self_subst is not None and name in self_subst:
            prev = self_subst[name]
            # Drop this name from the substitution map to break recursion
            # when the previous value itself contains the same identifier.
            next_subst = {k: v for k, v in self_subst.items() if k != name}
            return _expand(prev, env, depth + 1, next_subst)
        if name in env.decls:
            jt, init, _ = env.decls[name]
            if _is_str_or_charseq(jt) and init is not None:
                return _expand(init, env, depth + 1, self_subst)
            return (StringPart.var(name, jt),)
        return (StringPart.var(name),)
    if t == "method_invocation":
        return _expand_method_call(node, env, depth)
    if t == "field_access":
        return (StringPart.var(node_text(node, env.src)),)
    # Default: opaque.
    return (StringPart.var(node_text(node, env.src)),)


def _expand_method_call(node, env: _Env, depth: int) -> tuple[StringPart, ...]:
    name_node = node.child_by_field_name("name")
    obj_node = node.child_by_field_name("object")
    name = node_text(name_node, env.src) if name_node else ""

    # x.toString() → expand x.
    if name == "toString" and obj_node is not None:
        return _expand(obj_node, env, depth + 1)

    # String.format("…", a, b) and MessageFormat.format(...): expand the
    # format string and treat trailing args as opaque vars in positional
    # order. The placeholder skeleton (%s / {0}) survives in literals.
    if name == "format" and obj_node is not None:
        recv = node_text(obj_node, env.src)
        if recv in ("String", "java.lang.String", "MessageFormat",
                    "java.text.MessageFormat"):
            args = node.child_by_field_name("arguments")
            named = [c for c in (args.children if args else []) if c.is_named]
            if named:
                fmt_parts = list(_expand(named[0], env, depth + 1))
                arg_parts = []
                for a in named[1:]:
                    arg_parts.extend(_expand(a, env, depth + 1))
                return tuple(_merge(fmt_parts + arg_parts))

    # Unknown call: opaque.
    return (StringPart.var(node_text(node, env.src)),)


def _merge(parts):
    out: list[StringPart] = []
    for p in parts:
        if out and p.kind == "literal" and out[-1].kind == "literal":
            out[-1] = StringPart.lit(out[-1].value + p.value)
        else:
            out.append(p)
    return out


_ESC_RE = re.compile(r"\\(.)")


def _unquote(s: str) -> str:
    if not (s.startswith('"') and s.endswith('"')):
        return s
    body = s[1:-1]

    def sub(m: re.Match[str]) -> str:
        ch = m.group(1)
        return {"n": "\n", "t": "\t", "r": "\r", '"': '"',
                "\\": "\\", "'": "'", "b": "\b", "f": "\f", "0": "\0"}.get(ch, ch)

    return _ESC_RE.sub(sub, body)


# ---------------------------------------------------------------------------
# slice_sink_argument
# ---------------------------------------------------------------------------


def slice_sink_argument(java_src: str, sink_line: int) -> SliceResult | SliceAbstention:
    """AST-driven slice. Falls back to regex slicer if tree-sitter unavailable."""
    try:
        tree, src_bytes = parse_java(java_src)
    except TreeSitterUnavailable:
        from core.slicer import _slice_sink_argument_regex
        return _slice_sink_argument_regex(java_src, sink_line)

    # Find sink call on the exact line.
    sinks: list = []
    _collect_sink_nodes(tree.root_node, src_bytes, sinks)
    sink_node = next(
        (n for n in sinks if n.start_point[0] + 1 == sink_line),
        None,
    )
    if sink_node is None:
        return SliceAbstention("sink_not_found",
                               f"no sink call on line {sink_line}")

    method_node = _enclosing_method(sink_node)
    if method_node is None:
        return SliceAbstention("no_enclosing_method",
                               f"line {sink_line} is not inside a recognized method")

    env = _build_env(method_node, src_bytes)

    # Extract first argument expression node.
    args = sink_node.child_by_field_name("arguments")
    if args is None or args.named_child_count == 0:
        return SliceAbstention("no_sink_argument",
                               "could not extract sink argument")
    arg_node = args.named_child(0)
    arg_text = node_text(arg_node, src_bytes).strip()

    sink_var = arg_text if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", arg_text) else None

    parts = _expand(arg_node, env)
    parts = tuple(_merge(list(parts)))

    if not any(p.kind == "literal" for p in parts):
        return SliceAbstention("no_static_sql_skeleton",
                               "slice produced no literal SQL fragments")

    method_text = node_text(method_node, src_bytes)
    method_start_line = method_node.start_point[0] + 1
    call_text = node_text(sink_node, src_bytes)

    decls_to_remove: tuple[str, ...] = ()
    if sink_var is not None and sink_var in env.decls:
        _, _, decl_node = env.decls[sink_var]
        if decl_node is not None and decl_node.type == "local_variable_declaration":
            decls_to_remove = (node_text(decl_node, src_bytes),)

    return SliceResult(
        parts=parts,
        method_text=method_text,
        method_start_line=method_start_line,
        sink_call_text=call_text,
        sink_call_line=sink_line,
        sink_var_name=sink_var,
        declarations_to_remove=decls_to_remove,
    )


def _collect_sink_nodes(node, src_bytes: bytes, out: list) -> None:
    if node.type == "method_invocation":
        name_node = node.child_by_field_name("name")
        if name_node is not None and node_text(name_node, src_bytes) in _SINK_APIS:
            out.append(node)
    for ch in node.children:
        _collect_sink_nodes(ch, src_bytes, out)


def _enclosing_method(node):
    cur = node.parent
    while cur is not None:
        if cur.type in ("method_declaration", "constructor_declaration"):
            return cur
        cur = cur.parent
    return None


def infer_sem_type(java_type: str) -> str:
    return _java_type_to_sem(java_type)
