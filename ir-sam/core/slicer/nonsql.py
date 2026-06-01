"""Stage B --- Java slicer for non-SQL sinks (Phase 4).

The legacy regex slicer in :mod:`core.slicer` only locates SQL sink
APIs (``executeQuery``/``execute``/...). The Phase 4 interpreters
(shell, LDAP, XPath) sink through different Java APIs, so this module
provides a thin, reusable locator that drives the *same* textual
definition-use machinery (``_scan_locals`` / ``_expand_expr``) used by
the SQL slicer.

For each interpreter we:

1. find the sink call on the requested line,
2. extract the relevant argument (command for shell, filter for LDAP,
   query for XPath),
3. expand it into ordered literal/variable :class:`StringPart` parts,
4. return a :class:`SliceResult` whose ``sink_call_text`` spans the full
   invocation (so the Stage-F rewriter can replace it verbatim).

When the sink shape is not recognized the function returns a typed
:class:`SliceAbstention`, preserving the sound-or-abstain contract.
"""

from __future__ import annotations

import re

from core.slicer import (
    SliceAbstention,
    SliceResult,
    _balanced_arg,
    _expand_expr,
    _find_enclosing_method,
    _scan_locals,
    _scan_method_params,
    _skip_string,
)


# Sink locators: each regex matches from the start of the sink
# expression through the argument-bearing ``(``.
_SHELL_EXEC_RE = re.compile(
    r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(")
_LDAP_SEARCH_RE = re.compile(r"[A-Za-z_]\w*\s*\.\s*search\s*\(")
_XPATH_EVAL_RE = re.compile(r"[A-Za-z_][\w.]*\s*\.\s*(?:evaluate|compile)\s*\(")


def _split_top_level_args(body: str) -> list[str]:
    """Split a call-argument list on top-level commas."""
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
            i = _skip_string(body, i)
            continue
        elif c == "," and depth == 0:
            out.append(body[start:i].strip())
            start = i + 1
        i += 1
    tail = body[start:].strip()
    if tail:
        out.append(tail)
    return out


def _slice_java_call(
    java_src: str,
    sink_line: int,
    pattern: re.Pattern[str],
    arg_index: int,
    label: str,
) -> SliceResult | SliceAbstention:
    enclosing = _find_enclosing_method(java_src, sink_line)
    if enclosing is None:
        m_start, _m_end, m_start_line = 0, len(java_src), 1
        method_src = java_src
    else:
        m_start, m_end, m_start_line = enclosing
        method_src = java_src[m_start:m_end]

    target: re.Match[str] | None = None
    for m in pattern.finditer(method_src):
        abs_line = m_start_line + method_src.count("\n", 0, m.start())
        if abs_line == sink_line:
            target = m
            break
    if target is None:
        return SliceAbstention(
            "sink_not_found", f"{label}: no sink on line {sink_line}")

    lparen = target.end() - 1  # the matched argument-bearing "("
    args_str = _balanced_arg(method_src, lparen)
    if args_str is None:
        return SliceAbstention("no_sink_argument", f"{label}: unbalanced call")

    close = lparen + 1 + len(args_str)
    sink_call_text = method_src[target.start():close + 1]

    arglist = _split_top_level_args(args_str)
    if arg_index >= len(arglist):
        return SliceAbstention(
            "arg_index_out_of_range",
            f"{label}: argument {arg_index} not present")
    arg = arglist[arg_index].strip()

    env = _scan_locals(method_src)
    _scan_method_params(method_src, env)
    parts = _expand_expr(arg, env)
    if not any(p.kind == "literal" for p in parts):
        return SliceAbstention(
            "no_static_skeleton", f"{label}: no literal skeleton in argument")

    sink_var = arg if re.fullmatch(r"[A-Za-z_]\w*", arg) else None
    return SliceResult(
        parts=parts,
        method_text=method_src,
        method_start_line=m_start_line,
        sink_call_text=sink_call_text,
        sink_call_line=sink_line,
        sink_var_name=sink_var,
    )


def slice_java_shell(java_src: str, sink_line: int) -> SliceResult | SliceAbstention:
    return _slice_java_call(java_src, sink_line, _SHELL_EXEC_RE, 0, "java_shell")


def slice_java_ldap(java_src: str, sink_line: int) -> SliceResult | SliceAbstention:
    return _slice_java_call(java_src, sink_line, _LDAP_SEARCH_RE, 1, "java_ldap")


def slice_java_xpath(java_src: str, sink_line: int) -> SliceResult | SliceAbstention:
    return _slice_java_call(java_src, sink_line, _XPATH_EVAL_RE, 0, "java_xpath")


def _find(src: str, pattern: re.Pattern[str], api: str) -> list[tuple[int, str, str, str]]:
    out: list[tuple[int, str, str, str]] = []
    for m in pattern.finditer(src):
        line = src.count("\n", 0, m.start()) + 1
        lparen = m.end() - 1
        inner = _balanced_arg(src, lparen)
        if inner is None:
            text = m.group()
        else:
            close = lparen + 1 + len(inner)
            text = src[m.start():close + 1]
        recv = re.split(r"\s*\.\s*", m.group().strip())[0]
        out.append((line, recv, api, text))
    return out


def find_java_shell_sinks(src: str) -> list[tuple[int, str, str, str]]:
    return _find(src, _SHELL_EXEC_RE, "exec")


def find_java_ldap_sinks(src: str) -> list[tuple[int, str, str, str]]:
    return _find(src, _LDAP_SEARCH_RE, "search")


def find_java_xpath_sinks(src: str) -> list[tuple[int, str, str, str]]:
    return _find(src, _XPATH_EVAL_RE, "evaluate")
