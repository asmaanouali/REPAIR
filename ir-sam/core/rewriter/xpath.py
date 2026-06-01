"""Stage F --- XPath (CWE-643) rewriters.

XPath injection is closed by **variable binding**: attacker values are
bound to ``$name`` variables that the XPath engine treats as inert
string/number operands, never as query syntax
(``IRSAM.Soundness.Xpath``).

Hosts:

* **Python (lxml)** --- the query is parameterized with ``$vN``
  variables and the values are passed as keyword arguments to
  ``Element.xpath(query, v0=..., v1=...)``.
* **Java (javax.xml.xpath)** --- the query is parameterized with
  ``$vN`` variables and a ``setXPathVariableResolver`` is installed on
  the ``XPath`` object before the sink call.

The Python rewriter reconstructs the query from the slice's ordered
literal/variable parts (preserving the surrounding path/structure) and
strips the now-redundant quotes around each interpolated value. Both
rewriters **abstain** when the sink shape is not a single recognized
call form.
"""

from __future__ import annotations

import difflib
import re

from core.phi import PatchPlan, SetterCall
from core.rewriter import PatchResult, RewriteAbstention
from core.slicer import SliceResult


def _split_top_level_args(body: str) -> list[str]:
    out: list[str] = []
    depth = 0
    start = 0
    i = 0
    while i < len(body):
        c = body[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c in ("'", '"'):
            i = _skip_str(body, i)
            continue
        elif c == "," and depth == 0:
            out.append(body[start:i].strip())
            start = i + 1
        i += 1
    tail = body[start:].strip()
    if tail:
        out.append(tail)
    return out


def _skip_str(s: str, i: int) -> int:
    q = s[i]
    j = i + 1
    while j < len(s):
        if s[j] == "\\":
            j += 2
            continue
        if s[j] == q:
            return j + 1
        j += 1
    return j


def _unified_diff(original: str, patched: str, path: str = "source") -> str:
    return "".join(
        difflib.unified_diff(
            original.splitlines(keepends=True),
            patched.splitlines(keepends=True),
            fromfile=f"a/{path}", tofile=f"b/{path}",
        )
    )


def _ordered_value_exprs(plan: PatchPlan) -> list[SetterCall]:
    scalar = [s for s in plan.setter_calls if s.param_index >= 0]
    scalar.sort(key=lambda s: s.param_index)
    return scalar


def _build_var_query(slice_: SliceResult) -> tuple[str, int]:
    """Rebuild the query with ``$vN`` variables from the slice parts.

    Returns ``(query, n_vars)``. Quotes immediately surrounding a ``$vN``
    are stripped, since a bound variable reference must not be quoted.
    """
    pieces: list[str] = []
    vi = 0
    for p in slice_.parts:
        if p.kind == "literal":
            pieces.append(p.value)
        else:
            pieces.append(f"$v{vi}")
            vi += 1
    query = "".join(pieces)
    query = re.sub(r"'(\$v\d+)'", r"\1", query)
    query = re.sub(r'"(\$v\d+)"', r"\1", query)
    return query, vi


# --- Python ------------------------------------------------------------------


def synthesize_python_xpath_patch(
    src: str,
    slice_: SliceResult,
    plan: PatchPlan,
) -> PatchResult:
    if plan.allowlist_guards:
        raise RewriteAbstention(
            "python_xpath: identifier allow-list guards not supported"
        )
    call = slice_.sink_call_text
    if call not in src:
        raise RewriteAbstention("python_xpath: could not locate sink call text")

    open_paren = call.find("(")
    funcname = call[:open_paren].strip()
    method = funcname.rsplit(".", 1)[-1]
    if method != "xpath":
        raise RewriteAbstention(
            f"python_xpath: only Element.xpath() is supported, got {method!r}"
        )

    body = call[open_paren + 1: call.rfind(")")]
    args = _split_top_level_args(body)
    if not args:
        raise RewriteAbstention("python_xpath: no query argument")

    query, n_vars = _build_var_query(slice_)
    setters = _ordered_value_exprs(plan)
    if n_vars != len(setters):
        raise RewriteAbstention(
            f"python_xpath: variable/value count mismatch "
            f"({n_vars} vars, {len(setters)} values)"
        )

    kwargs = [f"v{i}={s.host_expr}" for i, s in enumerate(setters)]
    new_args = [_py_str_literal(query)] + args[1:] + kwargs
    new_call = f"{funcname}(" + ", ".join(new_args) + ")"

    patched = src.replace(call, new_call, 1)
    return PatchResult(
        original_source=src,
        patched_source=patched,
        unified_diff=_unified_diff(src, patched),
        connection_var="",
        used_imports=(),
    )


def _py_str_literal(s: str) -> str:
    return repr(s)


# --- Java --------------------------------------------------------------------


def synthesize_java_xpath_patch(
    src: str,
    slice_: SliceResult,
    plan: PatchPlan,
) -> PatchResult:
    if plan.allowlist_guards:
        raise RewriteAbstention(
            "java_xpath: identifier allow-list guards not supported"
        )
    call = slice_.sink_call_text
    if call not in src:
        raise RewriteAbstention("java_xpath: could not locate sink call text")

    open_paren = call.find("(")
    funcname = call[:open_paren].strip()
    method = funcname.rsplit(".", 1)[-1]
    if method not in ("evaluate", "compile"):
        raise RewriteAbstention(
            f"java_xpath: only XPath.evaluate/compile supported, got {method!r}"
        )
    receiver = funcname.rsplit(".", 1)[0]
    if not receiver:
        raise RewriteAbstention("java_xpath: cannot determine XPath receiver")

    body = call[open_paren + 1: call.rfind(")")]
    args = _split_top_level_args(body)
    if not args:
        raise RewriteAbstention("java_xpath: no query argument")

    query, n_vars = _build_var_query(slice_)
    setters = _ordered_value_exprs(plan)
    if n_vars != len(setters):
        raise RewriteAbstention(
            f"java_xpath: variable/value count mismatch "
            f"({n_vars} vars, {len(setters)} values)"
        )

    args[0] = _java_str_literal(query)
    new_call = f"{funcname}(" + ", ".join(args) + ")"

    # Build a nested-ternary XPathVariableResolver lambda binding each $vN.
    resolver = _build_java_resolver(setters)
    indent = _line_indent(src, call)
    resolver_stmt = f"{indent}{receiver}.setXPathVariableResolver({resolver});\n"

    # Insert the resolver statement on its own line immediately before the
    # line that contains the sink call.
    patched = src.replace(call, new_call, 1)
    line_start = _line_start_index(patched, new_call)
    patched = patched[:line_start] + resolver_stmt + patched[line_start:]

    return PatchResult(
        original_source=src,
        patched_source=patched,
        unified_diff=_unified_diff(src, patched),
        connection_var="",
        used_imports=("javax.xml.xpath.XPathVariableResolver",),
    )


def _build_java_resolver(setters: list[SetterCall]) -> str:
    # __vn -> "v0".equals(__vn.getLocalPart()) ? (Object) host0
    #       : "v1".equals(__vn.getLocalPart()) ? (Object) host1 : null
    chain = "null"
    for i in reversed(range(len(setters))):
        host = setters[i].host_expr
        chain = (f'"v{i}".equals(__vn.getLocalPart()) ? (Object) ({host}) '
                 f': {chain}')
    return f"__vn -> {chain}"


def _java_str_literal(s: str) -> str:
    esc = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{esc}"'


def _line_indent(src: str, needle: str) -> str:
    idx = src.find(needle)
    if idx < 0:
        return ""
    line_start = src.rfind("\n", 0, idx) + 1
    m = re.match(r"[ \t]*", src[line_start:idx])
    return m.group(0) if m else ""


def _line_start_index(src: str, needle: str) -> int:
    idx = src.find(needle)
    if idx < 0:
        return 0
    return src.rfind("\n", 0, idx) + 1
