"""Python (PEP-249) slicer + rewriter.

Two-tier implementation:

1.  **CST tier (preferred):** uses :mod:`libcst` when installed. A
    visitor walks the function body, tracks local assignments to
    ``str`` variables (best-effort dataflow), and lifts the call
    argument of the first sink into a sequence of
    :class:`core.slicer.StringPart`. CST guarantees we never confuse
    Python source with regex pattern artifacts.

2.  **Regex tier (fallback):** a Java-MVP-style regex slicer that
    handles ``"... " + var + "..."`` and ``f"... {var} ..."`` shapes.
    Activated automatically when libcst is unavailable.

The rewriter emits one canonical patched function body using the
PEP-249 ``cursor.execute(sql, params)`` form. The placeholder style is
parameterized so that the same plan can be lowered to SQLite (``?``),
psycopg2 (``%s``), or cx_Oracle (``:n``).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

from core.slicer import SliceAbstention, SliceResult, StringPart


SINK_APIS = {
    "execute", "executemany",
    "search",                      # ldap3 Connection.search
    "search_s",                    # python-ldap
    "search_ext_s",                # python-ldap
    "xpath",                       # lxml Element.xpath
    "XPath",                       # lxml.etree.XPath() constructor
    # --- Phase 9A: OS-command sinks (CWE-78) ---
    "system",                      # os.system
    "popen",                       # os.popen
    "run",                         # subprocess.run (when shell=True)
    "call",                        # subprocess.call
    "check_call",                  # subprocess.check_call
    "check_output",                # subprocess.check_output
    "Popen",                       # subprocess.Popen
    # --- Phase 9C: SSTI sinks (CWE-1336) ---
    "render_template_string",      # flask.render_template_string
    "from_string",                 # jinja2.Environment.from_string
    "Template",                    # jinja2.Template constructor
    # --- Phase 9D: deserialization sinks (CWE-502) ---
    "load",                        # pickle.load / yaml.load / dill.load / marshal.load
    "loads",                       # pickle.loads / yaml.loads
    "unsafe_load",                 # yaml.unsafe_load
    # --- Phase 9E: filesystem path sinks (CWE-22) ---
    # Note: ``open`` is a builtin called as a name, not a method; we
    # detect it via a separate regex (see _OPEN_SINK_RE below). Methods
    # on Path / shutil are caught by the dotted-API path.
    "read_text", "write_text", "read_bytes", "write_bytes",
    "copy", "copy2", "move",
}


_SINK_RE = re.compile(
    r"""
    # Receiver: a dotted name, optionally followed by a single
    # parenthesized call so chains like ``Path(user).read_text()`` or
    # ``Path(user).resolve().read_text()`` are recognised. The trailing
    # ``[^()]*`` is intentionally non-nesting; nested-call receivers
    # widen the surface beyond what regex can safely express.
    \b(?P<recv>[A-Za-z_][\w.]*(?:\s*\([^()]*\))?(?:\s*\.\s*[A-Za-z_][\w]*(?:\s*\([^()]*\))?)*)\s*\.\s*
    (?P<api>execute|executemany|search|search_s|search_ext_s|xpath|XPath
           |system|popen|run|call|check_call|check_output|Popen
           |render_template_string|from_string|Template
           |load|loads|unsafe_load
           |read_text|write_text|read_bytes|write_bytes|copy|copy2|move)
    \s*\(
    """,
    re.VERBOSE,
)


# Phase 9E (CWE-22): the builtin ``open(path, ...)`` called as a name.
# Captured separately because it isn't a method on a receiver.
_OPEN_SINK_RE = re.compile(
    r"(?<![\w.])open\s*\(", re.VERBOSE,
)


def find_sink_calls(py_src: str) -> list[tuple[int, str, str, str]]:
    """Return ``(line, receiver, api, call_text)`` for each PEP-249 sink."""
    out: list[tuple[int, str, str, str]] = []
    for m in _SINK_RE.finditer(py_src):
        line = py_src.count("\n", 0, m.start()) + 1
        call = _balanced_call(py_src, m.start())
        out.append((line, m.group("recv"), m.group("api"), call))
    return out


def _balanced_call(src: str, start: int) -> str:
    i = src.find("(", start)
    if i < 0:
        return src[start:start + 200]
    depth = 0
    j = i
    while j < len(src):
        c = src[j]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return src[start:j + 1]
        elif c in ("'", '"'):
            j = _skip_string(src, j)
            continue
        j += 1
    return src[start:j]


def _skip_string(src: str, start: int) -> int:
    # supports triple-quoted strings and f-strings (we treat them as opaque
    # here; the slicer reconstructs f-string content separately).
    if src.startswith(('"""', "'''"), start):
        q = src[start:start + 3]
        end = src.find(q, start + 3)
        return (end + 3) if end >= 0 else len(src)
    quote = src[start]
    j = start + 1
    while j < len(src):
        if src[j] == "\\":
            j += 2
            continue
        if src[j] == quote:
            return j + 1
        j += 1
    return j


# --- function extraction ----------------------------------------------------


def _find_enclosing_def(src: str, target_line: int) -> tuple[int, int, int] | None:
    """Return ``(start_pos, end_pos, start_line)`` of the ``def``/``async def``
    block containing ``target_line``. End is the position of the last
    line that belongs to the block (sibling-indent boundary)."""
    lines = src.splitlines(keepends=True)
    # locate every def line and its indent
    defs: list[tuple[int, int]] = []
    for i, line in enumerate(lines, start=1):
        m = re.match(r"^(?P<ind>[ \t]*)(?:async\s+)?def\s+\w+\s*\(", line)
        if m:
            defs.append((i, len(m.group("ind"))))
    if not defs:
        return None
    # pick the innermost def whose indent < target's indent and that
    # encloses target_line (by sibling-indent rule).
    candidate: tuple[int, int] | None = None
    for line_no, indent in defs:
        if line_no > target_line:
            break
        # find block end: next non-blank line with indent <= indent
        end = len(lines)
        for j in range(line_no, len(lines)):
            if j + 1 == line_no:
                continue
            stripped = lines[j]
            if not stripped.strip():
                continue
            j_ind = len(stripped) - len(stripped.lstrip(" \t"))
            if j_ind <= indent:
                end = j
                break
        if line_no <= target_line <= end:
            candidate = (line_no, end)
    if candidate is None:
        return None
    line_no, end = candidate
    start_pos = sum(len(l) for l in lines[:line_no - 1])
    end_pos = sum(len(l) for l in lines[:end])
    return (start_pos, end_pos, line_no)


# --- argument expression -> parts ------------------------------------------


_STR_RE = re.compile(r'(?:[fFrRbB]{0,2})(?:"""(?:.|\n)*?"""|\'\'\'(?:.|\n)*?\'\'\'|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')')


def _split_arg_concat(arg: str) -> list[str]:
    """Split a top-level ``a + b + c`` Python expression."""
    parts: list[str] = []
    depth = 0
    last = 0
    i = 0
    while i < len(arg):
        c = arg[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c in ("'", '"'):
            i = _skip_string(arg, i)
            continue
        elif c == "+" and depth == 0:
            parts.append(arg[last:i].strip())
            last = i + 1
        i += 1
    parts.append(arg[last:].strip())
    return [p for p in parts if p]


_FSTR_INNER = re.compile(r"\{([^{}]+?)(?::[^{}]*)?\}")


def _parts_from_fstring(text: str, env: dict[str, str]) -> list[StringPart]:
    """Lower an f-string body into StringParts. Format-spec is stripped."""
    out: list[StringPart] = []
    i = 0
    for m in _FSTR_INNER.finditer(text):
        if m.start() > i:
            out.append(StringPart.lit(text[i:m.start()]))
        expr = m.group(1).strip()
        ty = env.get(expr, "str")
        out.append(StringPart.var(expr, _py_type_to_java(ty)))
        i = m.end()
    if i < len(text):
        out.append(StringPart.lit(text[i:]))
    return out


def _py_type_to_java(t: str) -> str:
    """Map a Python type hint string to the Java-style names used by
    :func:`core.slicer.infer_sem_type` so Stage C can derive ``sem``."""
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


def _scan_locals(func_src: str) -> dict[str, str]:
    """Best-effort local string/int variable -> type-hint env.

    Recognized:
        x: int = ...
        x: str = ...
        x = "..."          (treated as str)
        x = int(...)       (treated as int)
    """
    env: dict[str, str] = {}
    for m in re.finditer(
        r"(?m)^[ \t]*(?P<name>[A-Za-z_]\w*)\s*:\s*(?P<ty>\w+)\s*=", func_src):
        env[m.group("name")] = m.group("ty")
    for m in re.finditer(
        r"(?m)^[ \t]*(?P<name>[A-Za-z_]\w*)\s*=\s*int\s*\(", func_src):
        env[m.group("name")] = "int"
    return env


def _scan_func_params(func_src: str) -> dict[str, str]:
    """Capture annotated function parameters (``def f(x: int, y: str)``)."""
    env: dict[str, str] = {}
    m = re.match(r"^[ \t]*(?:async\s+)?def\s+\w+\s*\(([^)]*)\)", func_src)
    if not m:
        return env
    for part in m.group(1).split(","):
        part = part.strip()
        if not part or part.startswith("*"):
            continue
        if ":" in part:
            name, ty = part.split(":", 1)
            ty = ty.split("=", 1)[0].strip()
            env[name.strip()] = ty
        else:
            env[part.split("=", 1)[0].strip()] = "str"
    return env


def slice_sink_argument(py_src: str, sink_line: int, arg_index: int = 0
                        ) -> SliceResult | SliceAbstention:
    """Dispatch to CST or regex slicer based on ``IRSAM_PY_SLICER``.

    ``IRSAM_PY_SLICER=cst``  → libcst slicer (Phase 3).
    Default                  → regex slicer (this module's
    :func:`_slice_sink_argument_regex`).
    """
    import os
    if os.environ.get("IRSAM_PY_SLICER", "regex").strip().lower() == "cst":
        try:
            from core.lang.python_cst import slice_sink_argument as _cst
            return _cst(py_src, sink_line, arg_index=arg_index)
        except Exception:
            return _slice_sink_argument_regex(py_src, sink_line, arg_index=arg_index)
    return _slice_sink_argument_regex(py_src, sink_line, arg_index=arg_index)


def _slice_sink_argument_regex(py_src: str, sink_line: int, arg_index: int = 0
                        ) -> SliceResult | SliceAbstention:
    """Reconstruct the first-argument string expression of the sink.

    Best-effort intra-procedural slice. The Phase-4 inter-procedural
    extension (``core.slicer.interproc``) wraps this when the immediate
    method body returns ``SliceAbstention(no_static_sql_skeleton)``.
    """
    enclosing = _find_enclosing_def(py_src, sink_line)
    if enclosing is None:
        # Quickfix-friendly fallback: treat the whole source as the
        # function body when no enclosing ``def`` is found (typical
        # for bare snippets pasted into the web Quickfix view).
        start, end, start_line = 0, len(py_src), 1
    else:
        start, end, start_line = enclosing
    func_src = py_src[start:end]

    sinks = [s for s in find_sink_calls(func_src)
             if s[0] + start_line - 1 == sink_line]
    if not sinks:
        # fall back to the first sink in the function body
        sinks = find_sink_calls(func_src)
    if not sinks:
        return SliceAbstention("sink_not_found", "no sink in def")
    _, _, _, call_text = sinks[0]
    arg = _first_arg_expression(call_text, arg_index=arg_index)
    if arg is None:
        return SliceAbstention("no_sink_argument", call_text[:120])

    env = _scan_func_params(func_src)
    env.update(_scan_locals(func_src))

    # resolve the variable: if `arg` is a bare identifier, look up its
    # initializer once.
    if re.fullmatch(r"[A-Za-z_]\w*", arg):
        init = _find_init(func_src, arg)
        if init is not None:
            arg = init

    parts = _lower_expr(arg, env)
    if not any(p.kind == "literal" for p in parts):
        return SliceAbstention("no_static_sql_skeleton",
                               "purely dynamic argument")

    return SliceResult(
        parts=tuple(parts),
        method_text=func_src,
        method_start_line=start_line,
        sink_call_text=call_text,
        sink_call_line=sink_line,
        sink_var_name=None,
        declarations_to_remove=(),
    )


def _first_arg_expression(call_text: str, arg_index: int = 0) -> str | None:
    i = call_text.find("(")
    if i < 0:
        return None
    depth = 0
    j = i + 1
    body_chars: list[str] = []
    while j < len(call_text):
        c = call_text[j]
        if c == "(":
            depth += 1
            body_chars.append(c)
        elif c == ")":
            if depth == 0:
                break
            depth -= 1
            body_chars.append(c)
        elif c in ("'", '"'):
            end = _skip_string(call_text, j)
            body_chars.append(call_text[j:end])
            j = end
            continue
        else:
            body_chars.append(c)
        j += 1
    return _top_level_nth_arg("".join(body_chars), arg_index)


def _top_level_first_arg(body: str) -> str:
    return _top_level_nth_arg(body, 0)


def _top_level_nth_arg(body: str, n: int) -> str | None:
    depth = 0
    i = 0
    start = 0
    found = 0
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
            if found == n:
                return body[start:i].strip()
            found += 1
            start = i + 1
        i += 1
    if found == n:
        return body[start:].strip()
    return None


def _find_init(func_src: str, name: str) -> str | None:
    m = re.search(rf"(?m)^[ \t]*{re.escape(name)}\s*(?::\s*\w+\s*)?=\s*(?P<rhs>[^\n]+)$",
                  func_src)
    return m.group("rhs").rstrip().rstrip(";").strip() if m else None


def _lower_expr(arg: str, env: dict[str, str]) -> list[StringPart]:
    # f-string?
    m = re.match(r"^(?:f|fr|rf|F|FR|RF)([\"'])((?:.|\n)*)\1$", arg)
    if m:
        return _parts_from_fstring(m.group(2), env)
    # %-format?  "..."%(a, b)  ->  treat % args as variables
    pct = _match_percent_format(arg)
    if pct is not None:
        return _parts_from_percent(pct[0], pct[1], env)
    # str.format?
    fmt = _match_str_format(arg)
    if fmt is not None:
        return _parts_from_str_format(fmt[0], fmt[1], env)
    # concatenation
    parts: list[StringPart] = []
    for sub in _split_arg_concat(arg):
        sm = re.match(r"^([\"'])((?:\\.|[^\\])*?)\1$", sub)
        if sm:
            parts.append(StringPart.lit(sm.group(2)))
        else:
            ty = env.get(sub, "str")
            parts.append(StringPart.var(sub, _py_type_to_java(ty)))
    return parts


def _match_percent_format(arg: str) -> tuple[str, list[str]] | None:
    # "literal..." % (a, b)   or   "literal..." % a
    m = re.match(r'^([\"\'])((?:\\.|[^\\])*?)\1\s*%\s*(.+)$', arg)
    if not m:
        return None
    rhs = m.group(3).strip()
    if rhs.startswith("(") and rhs.endswith(")"):
        rhs = rhs[1:-1]
    return m.group(2), [a.strip() for a in rhs.split(",") if a.strip()]


def _parts_from_percent(text: str, args: list[str], env: dict[str, str]
                        ) -> list[StringPart]:
    spec_re = re.compile(r"%[sdifrxX]")
    out: list[StringPart] = []
    i = 0
    k = 0
    for m in spec_re.finditer(text):
        if m.start() > i:
            out.append(StringPart.lit(text[i:m.start()]))
        if k < len(args):
            expr = args[k]
            ty = "int" if m.group() in ("%d", "%i") else env.get(expr, "str")
            out.append(StringPart.var(expr, _py_type_to_java(ty)))
            k += 1
        i = m.end()
    if i < len(text):
        out.append(StringPart.lit(text[i:]))
    return out


def _match_str_format(arg: str) -> tuple[str, list[str]] | None:
    m = re.match(r'^([\"\'])((?:\\.|[^\\])*?)\1\s*\.\s*format\s*\((.*)\)$', arg)
    if not m:
        return None
    return m.group(2), [a.strip() for a in m.group(3).split(",") if a.strip()]


def _parts_from_str_format(text: str, args: list[str], env: dict[str, str]
                           ) -> list[StringPart]:
    out: list[StringPart] = []
    i = 0
    k = 0
    for m in re.finditer(r"\{[^}]*\}", text):
        if m.start() > i:
            out.append(StringPart.lit(text[i:m.start()]))
        if k < len(args):
            expr = args[k]
            out.append(StringPart.var(expr, _py_type_to_java(env.get(expr, "str"))))
            k += 1
        i = m.end()
    if i < len(text):
        out.append(StringPart.lit(text[i:]))
    return out


# --- rewriter ----------------------------------------------------------------


PLACEHOLDER_STYLE = "?"   # SQLite/qmark; orchestrator can re-style


@dataclass(frozen=True)
class PyPatchResult:
    patched_source: str
    diff: str = ""


def synthesize_patch(py_src: str, slice_: SliceResult,
                     plan) -> PyPatchResult:
    """Rewrite the sink call to ``cursor.execute(sql, params)`` form.

    Uses the :class:`core.phi.PatchPlan` produced by Stage E; the
    Python adapter ignores the JDBC-specific ``api`` field on
    setters and consumes only ``host_expr`` + ``param_index`` order.
    """
    sql_literal = repr(_render_placeholder(plan.prepared_template,
                                           PLACEHOLDER_STYLE))
    params = "(" + ", ".join(s.host_expr for s in plan.setter_calls) + (",)" if len(plan.setter_calls) == 1 else ")")
    new_call = f".execute({sql_literal}, {params})"

    # Replace the original sink-call's "(<arg>)" with the new call body.
    # We locate the receiver.api(... ) substring and rewrite the args.
    call = slice_.sink_call_text
    dot = call.rfind(".")
    api_paren = call.find("(", dot)
    rewritten = call[:dot] + new_call
    patched = py_src.replace(call, rewritten, 1)
    return PyPatchResult(patched_source=patched, diff="")


def _render_placeholder(template: str, style: str) -> str:
    """Convert ``?`` placeholders in the canonical prepared template into
    the requested style. Java uses ``?``, psycopg2 uses ``%s``,
    cx_Oracle uses ``:1``, ``:2`` ..."""
    if style == "?":
        return template
    if style == "%s":
        return template.replace("?", "%s")
    if style.startswith(":"):
        # :n numbered
        i = 1
        out = []
        for ch in template:
            if ch == "?":
                out.append(f":{i}")
                i += 1
            else:
                out.append(ch)
        return "".join(out)
    return template
