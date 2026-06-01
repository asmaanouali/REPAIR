"""System-Dependence-Graph (SDG) slicer: global, inter-procedural.

This module turns the *local* (intra-procedural) slice into a *global*
one. When the SQL string that reaches a sink is not assembled inside the
sink's own method -- it is returned by a helper, a service, or a DAO in
another file -- this slicer follows the value-flow backward across method
and file boundaries and performs **selective, controlled inlining**:

* It resolves each call along the flow to a concrete method using the
  project-wide :class:`~core.slicer.project.ProjectModel` (including
  ``@Autowired`` / injected-field dispatch, Spring/Hibernate aware).
* It inlines only methods that are *provably pure string builders*
  (single ``return`` of a String expression, no side effects, matching
  arity) -- the same sound side-conditions the one-hop
  :mod:`core.slicer.interproc` enforces, now applied transitively.
* It fuses the traversed methods into one synthetic snippet and re-runs
  the existing intra-procedural slicer on it, so Stages C..G of the
  pipeline are unchanged. The rewrite still lands at the *real* sink
  site -- inlined bodies are reconstruction context only.

Soundness is preserved by construction: any unresolved call, ambiguous
dispatch, impure helper, or depth-bound overrun yields a typed
``sdg_*`` abstention rather than a guess.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from core.slicer import (
    SliceAbstention,
    SliceResult,
    find_sink_calls,
    slice_sink_argument,
)
from core.slicer.interproc import (
    _enclosing_method_text,
    _is_side_effect_free,
    _single_return_expr,
)
from core.slicer.project import ProjectModel


DEFAULT_MAX_DEPTH = 5


# --- provenance ---------------------------------------------------------------


@dataclass(frozen=True)
class InlineStep:
    """One inter-procedural hop taken by the SDG slicer."""

    callee: str
    owner: str | None
    file: Path
    header_line: int


@dataclass(frozen=True)
class SdgTrace:
    """Provenance for a global slice: the chain of inlined methods."""

    sink_file: Path
    steps: tuple[InlineStep, ...] = ()
    merged_source: str = ""
    tainted_params: tuple[str, ...] = ()

    @property
    def crossed_files(self) -> tuple[Path, ...]:
        seen: list[Path] = [self.sink_file]
        for s in self.steps:
            if s.file not in seen:
                seen.append(s.file)
        return tuple(seen)


# --- call extraction ----------------------------------------------------------


@dataclass(frozen=True)
class _FlowCall:
    recv: str | None        # receiver chain, e.g. "this.svc" / "repo" / None
    name: str               # method name
    args: tuple[str, ...]
    text: str               # exact substring in source to splice over


def _balanced(src: str, open_idx: int, opener: str, closer: str) -> int:
    depth = 0
    i = open_idx
    while i < len(src):
        c = src[i]
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _split_top_level(args: str) -> tuple[str, ...]:
    out: list[str] = []
    depth = 0
    last = 0
    for i, c in enumerate(args):
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            out.append(args[last:i].strip())
            last = i + 1
    tail = args[last:].strip()
    if tail or out:
        out.append(tail)
    return tuple(a for a in out if a != "" or len(out) > 1)


def _parse_outer_call(expr: str) -> _FlowCall | None:
    """If ``expr`` is exactly ``[recv.]name(args)`` return its parts."""
    expr = expr.strip()
    if not expr.endswith(")"):
        return None
    lpar = expr.find("(")
    if lpar < 0:
        return None
    # the matching ) must be the last char for this to be a single call
    close = _balanced(expr, lpar, "(", ")")
    if close != len(expr) - 1:
        return None
    head = expr[:lpar].strip()
    m = re.fullmatch(r"(?:(?P<recv>[\w.]+)\.)?(?P<name>[A-Za-z_]\w*)", head)
    if not m:
        return None
    args = _split_top_level(expr[lpar + 1:close])
    if args == ("",):
        args = ()
    return _FlowCall(
        recv=m.group("recv"),
        name=m.group("name"),
        args=args,
        text=expr,
    )


def _rhs_for_var(method_text: str, var: str, before_idx: int) -> str | None:
    """Return the RHS expression of the last assignment to ``var``.

    Scans ``Type var = <rhs>;`` and ``var = <rhs>;`` occurring before
    ``before_idx`` (the sink position) and returns the *exact* RHS
    substring (without the trailing ``;``) so it can be spliced over.
    """
    pat = re.compile(rf"(?:[A-Za-z_][\w.<>\[\]]*\s+)?\b{re.escape(var)}\s*=\s*")
    best: str | None = None
    for m in pat.finditer(method_text):
        if m.end() > before_idx:
            break
        semi = method_text.find(";", m.end())
        if semi < 0:
            continue
        best = method_text[m.end():semi].strip()
    return best


def _find_flow_call(src: str, sink_line: int) -> _FlowCall | None:
    """Find the opaque method call whose return value reaches the sink."""
    method_text = _enclosing_method_text(src, sink_line)
    if method_text is None:
        method_text = src
    # locate the sink call within the method and grab its first argument
    sinks = find_sink_calls(method_text)
    target = None
    for ln, _recv, _api, call_text in sinks:
        idx = method_text.find(call_text)
        if idx < 0:
            continue
        abs_line = method_text[:idx].count("\n")
        # method_text starts at some absolute line; compare relative offset
        target = (idx, call_text)
        break
    if target is None:
        return None
    _idx, call_text = target
    lpar = call_text.find("(")
    arg_close = _balanced(call_text, lpar, "(", ")")
    if arg_close < 0:
        return None
    first_arg = _split_top_level(call_text[lpar + 1:arg_close])
    if not first_arg:
        return None
    arg = first_arg[0].strip()

    sink_pos = method_text.find(call_text)
    # If the argument is a bare identifier, follow it to its initializer.
    if re.fullmatch(r"[A-Za-z_]\w*", arg):
        rhs = _rhs_for_var(method_text, arg, sink_pos)
        if rhs is not None:
            call = _parse_outer_call(rhs)
            if call is not None:
                return call
        return None
    # Otherwise the argument may itself be the call (e.g. executeQuery(build(x))).
    return _parse_outer_call(arg)


# --- callee resolution --------------------------------------------------------


_STRINGY_DECL_RE = re.compile(
    r"^(?:final\s+)?(?:String|StringBuilder|StringBuffer|CharSequence|var)\b")
_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)


def _helper_is_pure_single_return(body: str) -> bool:
    """Sound purity gate for selective inlining.

    A helper may be inlined only when, apart from the single ``return``
    of a String expression, its body contains nothing but benign local
    String declarations. Any bare statement (e.g. ``log(x);``), I/O, or
    mutation makes the inline unsound -> the SDG slicer abstains.
    """
    stripped = _COMMENT_RE.sub("", body)
    statements = [s.strip() for s in stripped.split(";") if s.strip()]
    return_seen = False
    for st in statements:
        if st.startswith("return"):
            return_seen = True
            continue
        # only String-typed local declarations are tolerated
        if not _STRINGY_DECL_RE.match(st) or "=" not in st:
            return False
    return return_seen


def _resolve_callee(project: ProjectModel, file: Path, call: _FlowCall):
    owner = project.find_enclosing_class(file)
    recv = call.recv
    if recv in (None, "this"):
        return project.resolve_method(call.name, owner=owner)
    # receiver chain: take the first segment as a field/local name
    head = recv.split(".")
    if head[0] == "this" and len(head) > 1:
        field_name = head[1]
    else:
        field_name = head[0]
    field_type = project.field_type(owner, field_name) if owner else None
    if field_type is not None:
        return project.resolve_method(call.name, owner=field_type)
    # unknown receiver type: accept only a globally unique method name
    return project.resolve_method(call.name)


# --- main ---------------------------------------------------------------------


def slice_global_traced(
    project: ProjectModel,
    file: Path | str,
    sink_line: int,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    tainted_params: tuple[str, ...] = (),
) -> tuple[SliceResult | SliceAbstention, SdgTrace]:
    """Global slice with multi-hop, cross-file selective inlining.

    Returns ``(result, trace)`` where ``trace`` records the chain of
    inlined methods (for provenance / auditing / tests).
    """
    file = Path(file)
    src = project.files.get(file)
    if src is None:
        try:
            src = file.read_text(encoding="utf-8")
            project.files[file] = src
        except OSError:
            return (
                SliceAbstention("sdg_callee_unresolved",
                                f"source for {file} unavailable"),
                SdgTrace(sink_file=file),
            )

    cur = src
    steps: list[InlineStep] = []

    for _depth in range(max_depth + 1):
        base = slice_sink_argument(cur, sink_line)
        if isinstance(base, SliceResult):
            return base, SdgTrace(
                sink_file=file, steps=tuple(steps),
                merged_source=cur, tainted_params=tainted_params)
        if base.reason not in {"no_static_sql_skeleton", "no_sink_argument"}:
            # an abstention unrelated to inlining (e.g. sink_not_found)
            return base, SdgTrace(
                sink_file=file, steps=tuple(steps), merged_source=cur,
                tainted_params=tainted_params)

        call = _find_flow_call(cur, sink_line)
        if call is None:
            return base, SdgTrace(
                sink_file=file, steps=tuple(steps), merged_source=cur,
                tainted_params=tainted_params)

        mdef = _resolve_callee(project, file, call)
        if mdef is None:
            reason = ("sdg_ambiguous_dispatch"
                      if project.methods_by_name.get(call.name)
                      else "sdg_callee_unresolved")
            return (
                SliceAbstention(reason,
                                f"call {call.recv or ''}.{call.name} "
                                f"could not be resolved to a single method"),
                SdgTrace(sink_file=file, steps=tuple(steps),
                         merged_source=cur, tainted_params=tainted_params),
            )

        ret = _single_return_expr(mdef.body)
        if ret is None:
            return (
                SliceAbstention("sdg_impure_helper",
                                f"{mdef.owner}.{mdef.name} is not a "
                                f"single-return string builder"),
                SdgTrace(sink_file=file, steps=tuple(steps),
                         merged_source=cur, tainted_params=tainted_params),
            )
        if not _is_side_effect_free(mdef.body):
            return (
                SliceAbstention("sdg_impure_helper",
                                f"{mdef.owner}.{mdef.name} has side effects"),
                SdgTrace(sink_file=file, steps=tuple(steps),
                         merged_source=cur, tainted_params=tainted_params),
            )
        if not _helper_is_pure_single_return(mdef.body):
            return (
                SliceAbstention("sdg_impure_helper",
                                f"{mdef.owner}.{mdef.name} mixes statements "
                                f"with its return"),
                SdgTrace(sink_file=file, steps=tuple(steps),
                         merged_source=cur, tainted_params=tainted_params),
            )
        if len(mdef.params) != len(call.args):
            return (
                SliceAbstention("sdg_impure_helper",
                                f"{mdef.owner}.{mdef.name} param/arg arity "
                                f"mismatch"),
                SdgTrace(sink_file=file, steps=tuple(steps),
                         merged_source=cur, tainted_params=tainted_params),
            )

        expr = ret
        for (pname, _ptype), actual in zip(mdef.params, call.args):
            expr = re.sub(rf"\b{re.escape(pname)}\b", f"({actual})", expr)

        new_cur = cur.replace(call.text, f"({expr})", 1)
        if new_cur == cur:
            # splice failed to match -- abstain rather than loop forever
            return (
                SliceAbstention("sdg_callee_unresolved",
                                f"could not splice call {call.name!r}"),
                SdgTrace(sink_file=file, steps=tuple(steps),
                         merged_source=cur, tainted_params=tainted_params),
            )
        cur = new_cur
        steps.append(InlineStep(
            callee=mdef.name, owner=mdef.owner,
            file=mdef.file, header_line=mdef.header_line))

    return (
        SliceAbstention("sdg_depth_exceeded",
                        f"inlining exceeded max_depth={max_depth}"),
        SdgTrace(sink_file=file, steps=tuple(steps), merged_source=cur,
                 tainted_params=tainted_params),
    )


def slice_global(
    project: ProjectModel,
    file: Path | str,
    sink_line: int,
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    tainted_params: tuple[str, ...] = (),
) -> SliceResult | SliceAbstention:
    """Convenience wrapper returning only the slice result."""
    result, _trace = slice_global_traced(
        project, file, sink_line,
        max_depth=max_depth, tainted_params=tainted_params)
    return result


__all__ = [
    "slice_global",
    "slice_global_traced",
    "SdgTrace",
    "InlineStep",
    "DEFAULT_MAX_DEPTH",
]
