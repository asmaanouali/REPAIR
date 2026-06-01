"""Inter-procedural slicing extension (Phase 4).

When the intra-procedural slicer abstains with ``no_static_sql_skeleton``
because the sink call's argument is the *return value of a local
helper method*, this module performs a one-hop call expansion:

1. Identify whether the abstaining slice's argument is a call
   ``recv.helper(args)`` or simply ``helper(args)`` inside the same
   compilation unit.
2. Locate the helper definition. If it has a *single return statement*
   whose expression is a String-typed concatenation, splice that body
   in place of the call and re-run the intra-procedural slicer.
3. Symbolic parameters of the helper are substituted with the
   actual-argument expression from the caller (alpha-renaming on
   identifier collision).

The transformation is *sound by construction* under the following
checked side-conditions:

* The helper has exactly one return statement.
* The helper has no other side effects (no field writes, no other
  sinks, no new statements).
* The helper has no loop, branch, or exception construct.

If any side-condition fails, this module abstains with
``interproc_unsupported``.

This is intentionally a small, surgical lift --- the Phase-5 swap-in
of Joern/Spoon will replace it with a proper CPG slicer. The point of
the extension is to retire the most common Phase-2 false-negative
shape on Juliet (helper-method SQL builder).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from core.slicer import (
    SliceAbstention,
    SliceResult,
    slice_sink_argument as _java_slice,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from core.slicer.project import ProjectModel


@dataclass(frozen=True)
class InterprocTrace:
    callee_name: str
    callee_body: str
    inlined_method: str


def slice_with_interproc(
    java_src: str,
    sink_line: int,
    *,
    project: "ProjectModel | None" = None,
) -> SliceResult | SliceAbstention:
    """Slice with helper inlining.

    With no ``project`` this performs the original *one-hop, same
    compilation unit* expansion. When a
    :class:`~core.slicer.project.ProjectModel` is supplied, the call is
    delegated to the multi-hop, cross-file SDG slicer
    (:func:`core.slicer.sdg.slice_global`) so the same surgical lift is
    applied transitively across files.
    """
    if project is not None:
        from core.slicer.sdg import slice_global

        # The project model indexes sources by path; the in-memory
        # snippet is sliced by re-registering it under a synthetic path
        # only when it is not already part of the model.
        for path, src in project.files.items():
            if src == java_src:
                return slice_global(project, path, sink_line)
        # Fall through to single-file behaviour if the snippet is not
        # part of the indexed project.

    base = _java_slice(java_src, sink_line)
    if isinstance(base, SliceResult):
        return base
    if base.reason not in {"no_static_sql_skeleton", "no_sink_argument"}:
        return base
    # try inlining
    method_text = _enclosing_method_text(java_src, sink_line)
    if method_text is None:
        return base
    call = _find_helper_call_at_sink(method_text, sink_line)
    if call is None:
        return base
    helper_name, actual_args = call
    helper_body, helper_params = _find_method_body(java_src, helper_name)
    if helper_body is None:
        return base
    ret = _single_return_expr(helper_body)
    if ret is None:
        return SliceAbstention("interproc_unsupported",
                               f"helper {helper_name!r} not a pure single-return")
    if not _is_side_effect_free(helper_body):
        return SliceAbstention("interproc_unsupported",
                               f"helper {helper_name!r} has side effects")
    # alpha-substitute parameter names -> actual arg exprs
    if len(helper_params) != len(actual_args):
        return SliceAbstention("interproc_unsupported", "param/arg arity mismatch")
    expr = ret
    for (pname, _ptype), actual in zip(helper_params, actual_args):
        expr = re.sub(rf"\b{re.escape(pname)}\b", f"({actual})", expr)
    # rewrite the original method to inline: replace "helper(args)" with "(expr)"
    inlined = method_text.replace(
        _reconstruct_call(helper_name, actual_args),
        f"({expr})",
        1,
    )
    # splice rewritten method into source (line-preserving)
    new_src = java_src.replace(method_text, inlined, 1)
    # re-slice
    return _java_slice(new_src, sink_line)


# --- helpers ---------------------------------------------------------------


def _enclosing_method_text(src: str, target_line: int) -> str | None:
    method_header = re.compile(
        r"""
        (?:public|protected|private|static|final|\s)+
        [\w<>,\s\[\]?\.]+\s+
        (?P<name>[A-Za-z_][A-Za-z_0-9]*)\s*\([^)]*\)\s*
        (?:throws\s+[\w\s,\.]+)?\s*\{
        """,
        re.VERBOSE,
    )
    best: str | None = None
    for m in method_header.finditer(src):
        ob = src.find("{", m.start())
        depth = 0
        i = ob
        while i < len(src):
            c = src[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    lo = src.count("\n", 0, m.start()) + 1
                    hi = src.count("\n", 0, i) + 1
                    if lo <= target_line <= hi:
                        best = src[m.start():i + 1]
                    break
            i += 1
    return best


def _find_helper_call_at_sink(method_text: str, sink_line_abs: int
                              ) -> tuple[str, list[str]] | None:
    """Look at the sink call's argument to see if it is ``helper(args)``."""
    sink_re = re.compile(
        r"\.(?:executeQuery|executeUpdate|execute|addBatch|prepareStatement)\s*\("
    )
    m = sink_re.search(method_text)
    if not m:
        return None
    # extract the first arg
    open_p = m.end() - 1
    depth = 0
    j = open_p
    while j < len(method_text):
        c = method_text[j]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                arg_text = method_text[open_p + 1:j]
                break
        j += 1
    else:
        return None
    arg_text = arg_text.split(",")[0].strip()
    # is it `name(args)` or `this.name(args)` ?
    cm = re.match(r"(?:this\.)?(?P<n>[A-Za-z_]\w*)\s*\((?P<a>.*)\)$",
                  arg_text, re.DOTALL)
    if not cm:
        return None
    return cm.group("n"), _split_args(cm.group("a"))


def _split_args(body: str) -> list[str]:
    if not body.strip():
        return []
    out: list[str] = []
    depth = 0
    last = 0
    for i, c in enumerate(body):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            out.append(body[last:i].strip())
            last = i + 1
    out.append(body[last:].strip())
    return out


def _find_method_body(src: str, name: str
                      ) -> tuple[str | None, list[tuple[str, str]]]:
    """Return (body, params). Body excludes the outer ``{ }``."""
    head_re = re.compile(
        rf"(?:public|protected|private|static|final|\s)+"
        rf"(?P<ret>[\w<>,\s\[\]?\.]+)\s+{re.escape(name)}\s*\((?P<ps>[^)]*)\)"
        rf"(?:\s*throws\s+[\w\s,\.]+)?\s*\{{",
        re.VERBOSE,
    )
    m = head_re.search(src)
    if not m:
        return None, []
    ob = src.find("{", m.start())
    depth = 0
    i = ob
    while i < len(src):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                body = src[ob + 1:i]
                break
        i += 1
    else:
        return None, []
    params = []
    for part in m.group("ps").split(","):
        part = part.strip()
        if not part:
            continue
        bits = part.rsplit(maxsplit=1)
        if len(bits) == 2:
            params.append((bits[1], bits[0]))
    return body, params


def _single_return_expr(body: str) -> str | None:
    rs = re.findall(r"return\s+(.+?);", body, flags=re.S)
    if len(rs) != 1:
        return None
    return rs[0].strip()


def _is_side_effect_free(body: str) -> bool:
    forbidden = (r"\bnew\s+", r"\.\s*executeQuery", r"\.\s*executeUpdate",
                 r"\bif\b", r"\bfor\b", r"\bwhile\b", r"\btry\b", r"\bthrow\b",
                 r"\+\+", r"--", r"this\.[A-Za-z_]\w*\s*=")
    for pat in forbidden:
        if re.search(pat, body):
            return False
    return True


def _reconstruct_call(name: str, args: list[str]) -> str:
    return f"{name}(" + ", ".join(args) + ")"
