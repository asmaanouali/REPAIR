"""Python CST-driven slicer (Phase 3).

Replaces the regex-based slicer in :mod:`core.lang.python` for Python
SQL/LDAP/XPath/shell sinks. Opt-in via ``IRSAM_PY_SLICER=cst``; default
remains the regex tier until a release gate ratifies the CST tier.
Both implementations expose identical :class:`SliceResult` /
:class:`SliceAbstention` values for the shapes already covered, plus
the CST tier additionally handles:

* nested ``+`` concatenation with method calls
* augmented assignment (``sql += ...``) followed by sink use
* multiple reassignments (latest binding wins)
* ``str.format`` with kwarg substitution
* f-strings with format-spec / conversion
* dotted-name receivers (``self.cur.execute``)

The CST tier never silently drops a host expression: anything we
cannot statically lower becomes an opaque ``StringPart.var`` exactly as
the regex tier does, preserving the contract with stage D/E/F.
"""

from __future__ import annotations

import re
from typing import Iterable

from core.slicer import SliceAbstention, SliceResult, StringPart


# Re-use the sink API set declared in the regex module so the two
# implementations stay in lockstep.
from core.lang.python import SINK_APIS as _PY_SINK_APIS


_BUILTIN_OPEN = "open"


class _Unavailable(Exception):
    pass


def _import_cst():
    try:
        import libcst as cst
        import libcst.matchers  # noqa: F401 - ensure submodule is loaded
        import libcst.metadata  # noqa: F401
        return cst
    except Exception as exc:  # pragma: no cover - import guard
        raise _Unavailable(f"libcst not installed: {exc}") from exc


def _py_type_to_java(t: str) -> str:
    t = t.strip().lower()
    if t in ("int", "long"):
        return "int"
    if t in ("float", "decimal"):
        return "float"
    if t in ("bool", "boolean"):
        return "boolean"
    if t in ("bytes", "memoryview", "buffer"):
        return "byte"
    return "java.lang.String"


# ---------------------------------------------------------------------------
# find_sink_calls
# ---------------------------------------------------------------------------


def find_sink_calls(py_src: str) -> list[tuple[int, str, str, str]]:
    """CST counterpart of :func:`core.lang.python.find_sink_calls`."""
    try:
        cst = _import_cst()
    except _Unavailable:
        from core.lang.python import find_sink_calls as _regex
        return _regex(py_src)

    try:
        module = cst.parse_module(py_src)
    except cst.ParserSyntaxError:
        return []

    wrapper = cst.metadata.MetadataWrapper(module)
    positions = wrapper.resolve(cst.metadata.PositionProvider)
    code = wrapper.module.code

    out: list[tuple[int, str, str, str]] = []
    for node in cst.matchers.findall(wrapper.module, cst.matchers.Call()):
        api, recv = _classify_call(node, cst)
        if api is None:
            continue
        pos = positions[node]
        line = pos.start.line
        call_text = _node_code(node, cst, code)
        out.append((line, recv, api, call_text))
    return out


def _classify_call(call, cst) -> tuple[str | None, str]:
    """Return ``(api_or_None, receiver_text)`` for a ``Call`` node."""
    func = call.func
    # Builtin ``open(...)`` (no receiver).
    if isinstance(func, cst.Name) and func.value == _BUILTIN_OPEN:
        return ("open", "")
    if isinstance(func, cst.Attribute):
        api = func.attr.value
        if api in _PY_SINK_APIS:
            recv = _attribute_receiver_text(func.value, cst)
            return (api, recv)
    if isinstance(func, cst.Name) and func.value in _PY_SINK_APIS:
        # Bare ``execute(...)`` etc — rare but recognized.
        return (func.value, "")
    return (None, "")


def _attribute_receiver_text(node, cst) -> str:
    """Render a dotted-name receiver back to source-like text."""
    if isinstance(node, cst.Name):
        return node.value
    if isinstance(node, cst.Attribute):
        return f"{_attribute_receiver_text(node.value, cst)}.{node.attr.value}"
    if isinstance(node, cst.Call):
        return _attribute_receiver_text(node.func, cst)
    return ""


def _node_code(node, cst, full_code: str) -> str:
    """Best-effort source-text reconstruction for a CST node."""
    try:
        return cst.Module(body=[]).code_for_node(node)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# slice_sink_argument
# ---------------------------------------------------------------------------


def slice_sink_argument(py_src: str, sink_line: int, arg_index: int = 0
                        ) -> SliceResult | SliceAbstention:
    try:
        cst = _import_cst()
    except _Unavailable:
        from core.lang.python import slice_sink_argument as _regex
        return _regex(py_src, sink_line, arg_index=arg_index)

    try:
        module = cst.parse_module(py_src)
    except cst.ParserSyntaxError as exc:
        return SliceAbstention("parse_error", str(exc)[:200])

    wrapper = cst.metadata.MetadataWrapper(module)
    positions = wrapper.resolve(cst.metadata.PositionProvider)

    # Find the sink Call node whose start line matches ``sink_line``.
    sink_call = None
    for node in cst.matchers.findall(wrapper.module, cst.matchers.Call()):
        api, _recv = _classify_call(node, cst)
        if api is None:
            continue
        if positions[node].start.line == sink_line:
            sink_call = node
            break
    if sink_call is None:
        return SliceAbstention("sink_not_found",
                               f"no sink call on line {sink_line}")

    # Find enclosing function.
    func_node = _enclosing_function(wrapper.module, sink_call, cst)
    if func_node is None:
        return SliceAbstention("no_enclosing_method",
                               f"sink at line {sink_line} has no enclosing def")

    # Build local environment from the function.
    env = _build_env(func_node, cst)

    # Resolve nth argument expression.
    args = [a for a in sink_call.args if a.keyword is None]
    if arg_index >= len(args):
        return SliceAbstention("no_sink_argument",
                               f"call has fewer than {arg_index + 1} positional args")
    arg_expr = args[arg_index].value

    parts = tuple(_merge(list(_lower_expr(arg_expr, env, cst))))
    if not any(p.kind == "literal" for p in parts):
        return SliceAbstention("no_static_sql_skeleton",
                               "purely dynamic argument")

    func_start_line = positions[func_node].start.line
    func_text = cst.Module(body=[]).code_for_node(func_node)
    call_text = cst.Module(body=[]).code_for_node(sink_call)

    return SliceResult(
        parts=parts,
        method_text=func_text,
        method_start_line=func_start_line,
        sink_call_text=call_text,
        sink_call_line=sink_line,
        sink_var_name=None,
        declarations_to_remove=(),
    )


def _enclosing_function(module, target_node, cst):
    """Return the ``FunctionDef`` ancestor of ``target_node``, or None."""
    # libcst doesn't expose parent pointers; do a top-down search.
    found: list = []

    def search(node, ancestors):
        if node is target_node:
            for a in reversed(ancestors):
                if isinstance(a, cst.FunctionDef):
                    found.append(a)
                    return True
            return True
        for child in node.children:
            if search(child, ancestors + [node]):
                return True
        return False

    search(module, [])
    return found[0] if found else None


# ---------------------------------------------------------------------------
# Local environment + expression lowering
# ---------------------------------------------------------------------------


class _Env:
    """Local-variable env: ``name -> (py_type, init_expr_node)``."""

    __slots__ = ("decls",)

    def __init__(self):
        self.decls: dict[str, tuple[str, object | None]] = {}


def _build_env(func_node, cst) -> _Env:
    env = _Env()

    # Parameters with annotations.
    params = func_node.params
    for p in list(params.params) + list(params.kwonly_params):
        name = p.name.value
        ty = "str"
        if p.annotation is not None and isinstance(p.annotation.annotation, cst.Name):
            ty = p.annotation.annotation.value
        env.decls[name] = (ty, None)

    # Walk statements in lexical order so the latest binding wins.
    body = func_node.body
    stmts = list(body.body) if hasattr(body, "body") else []
    _scan_stmts(stmts, env, cst)
    return env


def _scan_stmts(stmts: Iterable, env: _Env, cst) -> None:
    for stmt in stmts:
        _scan_one(stmt, env, cst)


def _scan_one(stmt, env: _Env, cst) -> None:
    if isinstance(stmt, cst.SimpleStatementLine):
        for small in stmt.body:
            _scan_small(small, env, cst)
    elif isinstance(stmt, (cst.If, cst.While, cst.For, cst.Try, cst.With)):
        # Inline nested statements; we don't model control flow, just
        # latest binding seen lexically.
        for child in stmt.children:
            if hasattr(child, "body") and hasattr(child.body, "body"):
                _scan_stmts(child.body.body, env, cst)


def _scan_small(node, env: _Env, cst) -> None:
    if isinstance(node, cst.Assign):
        for tgt in node.targets:
            if isinstance(tgt.target, cst.Name):
                name = tgt.target.value
                ty = _infer_type_from_expr(node.value, env, cst)
                env.decls[name] = (ty, node.value)
    elif isinstance(node, cst.AnnAssign):
        if isinstance(node.target, cst.Name):
            name = node.target.value
            ty = node.annotation.annotation.value if isinstance(
                node.annotation.annotation, cst.Name) else "str"
            env.decls[name] = (ty, node.value)
    elif isinstance(node, cst.AugAssign):
        if isinstance(node.target, cst.Name):
            name = node.target.value
            prev_ty, prev = env.decls.get(name, ("str", None))
            op = node.operator
            if isinstance(op, cst.AddAssign):
                # Fold ``x += Y`` as ``x = x + Y``.
                synth = ("CONCAT", prev, node.value)
                env.decls[name] = (prev_ty, synth)
            else:
                env.decls[name] = (prev_ty, node.value)


def _infer_type_from_expr(expr, env: _Env, cst) -> str:
    if isinstance(expr, cst.SimpleString):
        return "str"
    if isinstance(expr, cst.FormattedString):
        return "str"
    if isinstance(expr, cst.Integer):
        return "int"
    if isinstance(expr, cst.Float):
        return "float"
    if isinstance(expr, cst.Call) and isinstance(expr.func, cst.Name):
        return expr.func.value  # "int", "str", "float", ...
    if isinstance(expr, cst.Name) and expr.value in env.decls:
        return env.decls[expr.value][0]
    return "str"


# ---------------------------------------------------------------------------
# Expression → StringPart lowering
# ---------------------------------------------------------------------------


def _lower_expr(node, env: _Env, cst, depth: int = 0) -> list[StringPart]:
    if depth > 32:
        return [StringPart.var("…")]
    # CONCAT sentinel from AugAssign.
    if isinstance(node, tuple) and node and node[0] == "CONCAT":
        _, lhs, rhs = node
        parts: list[StringPart] = []
        if lhs is not None:
            parts.extend(_lower_expr(lhs, env, cst, depth + 1))
        if rhs is not None:
            parts.extend(_lower_expr(rhs, env, cst, depth + 1))
        return _merge(parts)
    if node is None:
        return []
    if isinstance(node, cst.SimpleString):
        return [StringPart.lit(_unquote_python(node.value))]
    if isinstance(node, cst.ConcatenatedString):
        # Implicit string concat: ``"a" "b"`` → "ab".
        left = _lower_expr(node.left, env, cst, depth + 1)
        right = _lower_expr(node.right, env, cst, depth + 1)
        return _merge(left + right)
    if isinstance(node, cst.FormattedString):
        out: list[StringPart] = []
        for part in node.parts:
            if isinstance(part, cst.FormattedStringText):
                # libcst preserves the raw text including any escapes.
                out.append(StringPart.lit(part.value))
            elif isinstance(part, cst.FormattedStringExpression):
                inner = _lower_expr(part.expression, env, cst, depth + 1)
                # Drop literal annotations inside expressions; treat as opaque
                # var fragments to keep the SQL skeleton intact.
                for ip in inner:
                    if ip.kind == "var":
                        out.append(ip)
                    else:
                        out.append(StringPart.var(ip.value))
        return _merge(out)
    if isinstance(node, cst.BinaryOperation):
        if isinstance(node.operator, cst.Add):
            return _merge(
                _lower_expr(node.left, env, cst, depth + 1)
                + _lower_expr(node.right, env, cst, depth + 1)
            )
        if isinstance(node.operator, cst.Modulo):
            # ``"…%s…" % (a, b)`` style format.
            return _lower_percent_format(node.left, node.right, env, cst, depth)
        return [StringPart.var(_render(node, cst))]
    if isinstance(node, cst.Integer):
        return [StringPart.lit(node.value)]
    if isinstance(node, cst.Float):
        return [StringPart.lit(node.value)]
    if isinstance(node, cst.Name):
        name = node.value
        if name in env.decls:
            ty, init = env.decls[name]
            if init is not None and ty in ("str", "String", "bytes"):
                return _lower_expr(init, env, cst, depth + 1)
            return [StringPart.var(name, _py_type_to_java(ty))]
        return [StringPart.var(name)]
    if isinstance(node, cst.Call):
        return _lower_call(node, env, cst, depth)
    if isinstance(node, cst.Attribute):
        return [StringPart.var(_render(node, cst))]
    # Default: opaque expression text.
    return [StringPart.var(_render(node, cst))]


def _lower_call(node, env: _Env, cst, depth: int) -> list[StringPart]:
    # str.format style: ``"…{name}…".format(a, b, c=…)``.
    if isinstance(node.func, cst.Attribute) and node.func.attr.value == "format":
        tpl = _lower_expr(node.func.value, env, cst, depth + 1)
        # Replace each ``{…}`` placeholder in tpl literals with the
        # matching argument expression lowered to a var.
        pos_args = [a for a in node.args if a.keyword is None]
        kw_args = {a.keyword.value: a.value for a in node.args if a.keyword is not None}
        return _splice_format(tpl, pos_args, kw_args, env, cst, depth + 1)
    return [StringPart.var(_render(node, cst))]


def _splice_format(tpl: list[StringPart], pos_args, kw_args,
                   env: _Env, cst, depth: int) -> list[StringPart]:
    out: list[StringPart] = []
    pos_idx = 0
    for p in tpl:
        if p.kind != "literal":
            out.append(p)
            continue
        text = p.value
        # Tokenize on {…} placeholders.
        chunks = re.split(r"(\{[^{}]*\})", text)
        for ch in chunks:
            if not ch:
                continue
            if ch.startswith("{") and ch.endswith("}"):
                body = ch[1:-1].split("!")[0].split(":")[0]
                if not body:
                    # Positional {} placeholder.
                    if pos_idx < len(pos_args):
                        out.extend(_lower_expr(pos_args[pos_idx].value, env, cst, depth))
                        pos_idx += 1
                    else:
                        out.append(StringPart.var(ch))
                elif body.isdigit():
                    i = int(body)
                    if i < len(pos_args):
                        out.extend(_lower_expr(pos_args[i].value, env, cst, depth))
                    else:
                        out.append(StringPart.var(ch))
                else:
                    if body in kw_args:
                        out.extend(_lower_expr(kw_args[body], env, cst, depth))
                    else:
                        out.append(StringPart.var(ch))
            else:
                out.append(StringPart.lit(ch))
    return _merge(out)


def _lower_percent_format(fmt_node, args_node, env: _Env, cst,
                          depth: int) -> list[StringPart]:
    tpl = _lower_expr(fmt_node, env, cst, depth + 1)
    # Args can be a tuple, a single expression, or a dict.
    args_exprs: list = []
    if isinstance(args_node, cst.Tuple):
        for elt in args_node.elements:
            args_exprs.append(elt.value)
    else:
        args_exprs.append(args_node)

    out: list[StringPart] = []
    arg_idx = 0
    for p in tpl:
        if p.kind != "literal":
            out.append(p)
            continue
        # Split on %-specifiers like %s, %d, %r, %(name)s, %5.2f.
        chunks = re.split(r"(%(?:\([^)]*\))?[-+ #0]*\d*(?:\.\d+)?[sdrfgxXobicue%])", p.value)
        for ch in chunks:
            if not ch:
                continue
            if ch == "%%":
                out.append(StringPart.lit("%"))
            elif ch.startswith("%"):
                if arg_idx < len(args_exprs):
                    arg = args_exprs[arg_idx]
                    parts = _lower_expr(arg, env, cst, depth + 1)
                    # Heuristic: if %d/%f, prefer numeric java_type.
                    if ch[-1] in "dixXob":
                        for q in parts:
                            if q.kind == "var" and q.java_type == "java.lang.String":
                                out.append(StringPart.var(q.value, "int"))
                            else:
                                out.append(q)
                    else:
                        out.extend(parts)
                    arg_idx += 1
                else:
                    out.append(StringPart.var(ch))
            else:
                out.append(StringPart.lit(ch))
    return _merge(out)


def _render(node, cst) -> str:
    try:
        return cst.Module(body=[]).code_for_node(node).strip()
    except Exception:
        return ""


def _merge(parts: Iterable[StringPart]) -> list[StringPart]:
    out: list[StringPart] = []
    for p in parts:
        if out and p.kind == "literal" and out[-1].kind == "literal":
            out[-1] = StringPart.lit(out[-1].value + p.value)
        else:
            out.append(p)
    return out


_ESC_RE = re.compile(r"\\(.)")


def _unquote_python(s: str) -> str:
    """Strip Python string-literal quotes and process common escapes."""
    # Handle prefixes like r, b, rb, u, etc.
    i = 0
    prefix = ""
    while i < len(s) and s[i] not in ("'", '"'):
        prefix += s[i].lower()
        i += 1
    body = s[i:]
    if not body:
        return s
    # Triple-quoted?
    for q in ('"""', "'''", '"', "'"):
        if body.startswith(q) and body.endswith(q) and len(body) >= 2 * len(q):
            inner = body[len(q):-len(q)]
            if "r" in prefix:
                return inner
            return _ESC_RE.sub(_esc_sub, inner)
    return body


def _esc_sub(m: re.Match[str]) -> str:
    ch = m.group(1)
    return {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\",
            "'": "'", "b": "\b", "f": "\f", "0": "\0"}.get(ch, ch)
