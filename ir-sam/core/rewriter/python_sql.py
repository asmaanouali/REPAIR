"""Python DB-API (PEP-249) parameterized-SQL rewriter (Phase 5).

Given:

* ``src`` --- the original Python source.
* ``slice_`` --- a :class:`~core.slicer.SliceResult` describing the
  sink call (``cursor.execute(<concat>)``) and the dead SQL-string
  variable declarations to remove.
* ``plan`` --- a :class:`~core.phi.PatchPlan` whose
  ``prepared_template`` contains DB-API placeholders (``?`` for
  ``sqlite3`` or ``%s`` for ``psycopg2``/``mysql.connector``) and
  whose ``setter_calls`` give the host expressions in textual order.

The rewriter supports:

* Scalar holes lowered to positional ``?`` placeholders with an
  args tuple bound to ``cursor.execute(sql, args)``.
* IN-list holes with cardinality ``MANY_BOUNDED``: expanded at
  runtime via ``", ".join(["?"] * len(host_list))`` and unpacked
  into the parameter tuple with ``*host_list``.
* Identifier holes guarded by a static frozenset allow-list. The
  patched source asserts ``host_expr in _ALLOWLIST_<name>`` and
  raises ``ValueError`` on miss, then interpolates the literal
  identifier into the SQL via ``str.replace``.

It abstains (:class:`~core.rewriter.RewriteAbstention`) when the
sink call cannot be located, when an identifier guard has no
declared host expression, or when an IN-list marker is declared
but its template token is missing.
"""

from __future__ import annotations

import difflib
import re

from core.phi import AllowlistGuard, PatchPlan, SetterCall
from core.rewriter import PatchResult, RewriteAbstention
from core.slicer import SliceResult


_PY_INDENT_RE = re.compile(r"^([ \t]*)")


def synthesize_python_sql_patch(
    src: str,
    slice_: SliceResult,
    plan: PatchPlan,
) -> PatchResult:
    """Rewrite a Python DB-API sink to a parameterized ``execute`` call."""
    src_lines = src.splitlines(keepends=True)
    sink_idx = slice_.sink_call_line - 1
    if sink_idx < 0 or sink_idx >= len(src_lines):
        raise RewriteAbstention("python_sql_rewriter: sink line out of range")
    if slice_.sink_call_text not in src:
        raise RewriteAbstention(
            "python_sql_rewriter: could not locate sink call text"
        )

    indent = _detect_indent(src_lines[sink_idx])

    # Partition setter calls
    scalar_setters: list[SetterCall] = []
    inlist_setters: list[SetterCall] = []
    for s in plan.setter_calls:
        if s.param_index == -1:
            inlist_setters.append(s)
        else:
            scalar_setters.append(s)
    scalar_setters.sort(key=lambda s: s.param_index)

    has_guards = bool(plan.allowlist_guards)
    has_inlist = bool(inlist_setters)
    needs_sql_var = has_guards or has_inlist

    pre_lines: list[str] = []
    template_literal = _python_string_literal(plan.prepared_template)

    if needs_sql_var:
        pre_lines.append(f"__irsam_sql = {template_literal}")

        # 1) Identifier holes: allow-list assertion + literal substitution
        for g in plan.allowlist_guards:
            if not g.host_expr:
                raise RewriteAbstention(
                    f"python_sql_rewriter: identifier hole {g.hole_name!r} "
                    f"has no host expression"
                )
            constant = _py_allowlist_name(g.allowlist_java_const, g.hole_name)
            bound = f"__irsam_g_{g.hole_name}"
            pre_lines.append(
                f"if {g.host_expr} not in {constant}:"
            )
            pre_lines.append(
                f"    raise ValueError("
                f"f\"IR-SAM: identifier not in allow-list: "
                f"{{{g.host_expr}!r}}\")"
            )
            pre_lines.append(f"{bound} = {g.host_expr}")
            pre_lines.append(
                f"__irsam_sql = __irsam_sql.replace("
                f"{_python_string_literal('{__GUARD_' + g.hole_name + '__}')}"
                f", {bound})"
            )

        # 2) IN-list holes: dynamic placeholders
        for s in inlist_setters:
            tok = f"__INLIST_{s.hole_name}__"
            if tok not in plan.prepared_template:
                raise RewriteAbstention(
                    f"python_sql_rewriter: IN-list token {tok!r} not in template"
                )
            list_var = f"__irsam_list_{s.hole_name}"
            pre_lines.append(f"{list_var} = tuple({s.host_expr})")
            pre_lines.append(
                f"__irsam_sql = __irsam_sql.replace("
                f"{_python_string_literal(tok)}, "
                f'", ".join(["?"] * len({list_var})))'
            )
        sql_expr = "__irsam_sql"
    else:
        sql_expr = template_literal

    # 3) Build args tuple
    args_parts: list[str] = []
    for s in scalar_setters:
        args_parts.append(s.host_expr)
    for s in inlist_setters:
        list_var = f"__irsam_list_{s.hole_name}"
        args_parts.append(f"*{list_var}")
    args_tuple = "(" + ", ".join(args_parts)
    # Single-element scalar tuples need a trailing comma; *unpack does not.
    if len(args_parts) == 1 and not args_parts[0].startswith("*"):
        args_tuple += ","
    args_tuple += ")"

    new_args = f"{sql_expr}, {args_tuple}"
    new_call = _rebuild_call(slice_.sink_call_text, new_args)

    original_line = src_lines[sink_idx]
    pre_block = "".join(indent + line + "\n" for line in pre_lines)
    if slice_.sink_call_text in original_line:
        rewritten_line = original_line.replace(
            slice_.sink_call_text, new_call, 1,
        )
        src_lines[sink_idx] = pre_block + rewritten_line
        patched = "".join(src_lines)
    else:
        # Multi-line sink call: textual replace across the whole source.
        patched = src.replace(slice_.sink_call_text, new_call, 1)
        if pre_block:
            # Insert the pre-block immediately before the sink line.
            out = patched.splitlines(keepends=True)
            out[sink_idx] = pre_block + out[sink_idx]
            patched = "".join(out)

    # 4) Remove dead SQL-string variable declarations.
    if slice_.declarations_to_remove:
        out_lines = patched.splitlines(keepends=True)
        for decl in slice_.declarations_to_remove:
            for i, line in enumerate(out_lines):
                if line.strip() == decl.strip():
                    out_lines[i] = ""
                    break
        patched = "".join(out_lines)

    diff = "".join(difflib.unified_diff(
        src.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile="a/before.py",
        tofile="b/after.py",
        lineterm="",
    ))

    return PatchResult(
        original_source=src,
        patched_source=patched,
        unified_diff=diff,
        connection_var="",        # not applicable to DB-API
        used_imports=(),          # no new imports needed
    )


# --- helpers -----------------------------------------------------------------


_CALL_HEAD_RE = re.compile(
    r"""^(?P<head>[A-Za-z_$][\w$.]*\s*\.\s*
         (?:execute|executemany)\s*\()""",
    re.VERBOSE,
)


def _rebuild_call(call_text: str, new_args_text: str) -> str:
    """Replace ``cursor.execute(<old args>)`` with the new arg list."""
    m = _CALL_HEAD_RE.match(call_text)
    if not m:
        raise RewriteAbstention(
            f"python_sql_rewriter: unrecognized call head: {call_text!r}"
        )
    return f"{m.group('head')}{new_args_text})"


def _python_string_literal(s: str) -> str:
    """Render ``s`` as a Python double-quoted string literal."""
    escaped = (s.replace("\\", "\\\\")
               .replace('"', '\\"')
               .replace("\n", "\\n")
               .replace("\r", "\\r")
               .replace("\t", "\\t"))
    return f'"{escaped}"'


def _detect_indent(line: str) -> str:
    m = _PY_INDENT_RE.match(line)
    return m.group(1) if m else ""


def _py_allowlist_name(java_const: str, hole_name: str) -> str:
    """Translate a Java-flavored constant name into a Python identifier.

    ``IrsamAllowlists.TABLES`` becomes ``_ALLOWLIST_TABLES``; a hole-only
    fallback uses the hole name itself.
    """
    if not java_const:
        return f"_ALLOWLIST_{hole_name.upper()}"
    tail = java_const.rsplit(".", 1)[-1]
    return f"_ALLOWLIST_{tail.upper()}"
