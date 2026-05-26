"""Stage F --- patch synthesis on Java source text.

Given the original ``.java`` source, a :class:`~core.slicer.SliceResult`
and a :class:`~core.phi.PatchPlan`, the rewriter produces a new source
string that uses ``PreparedStatement`` with parameter binding instead
of the original concatenation-based sink, *and* removes the now-dead
SQL-string variable declaration.

The rewriter is conservative and produces patches that are stable
under whitespace and unrelated lines (only the sink site and the SQL
variable declaration are touched).

Output: :class:`PatchResult` containing the patched source and a
unified diff (RFC-recommended format) for human review.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

from core.phi import AllowlistGuard, PatchPlan, SetterCall
from core.slicer import SliceResult


_PS_VAR = "__irsam_ps"
_SQL_VAR = "__irsam_sql"


@dataclass(frozen=True)
class PatchResult:
    original_source: str
    patched_source: str
    unified_diff: str
    connection_var: str
    used_imports: tuple[str, ...]


class RewriteAbstention(ValueError):
    """Raised when the rewriter cannot apply the patch (e.g. no connection)."""


# --- connection discovery -----------------------------------------------------


_CONN_DECL_RE = re.compile(
    r"\b(?:java\.sql\.)?Connection\s+(?P<name>[A-Za-z_][A-Za-z_0-9]*)\s*[=;]"
)
_CREATE_STMT_RE = re.compile(
    r"(?P<conn>[A-Za-z_][A-Za-z_0-9]*)\s*\.\s*createStatement\s*\("
)


def _find_connection(java_src: str, sink_line: int) -> str | None:
    """Return the most plausible connection-variable name.

    Heuristic: prefer a ``X.createStatement()`` call that appears
    before ``sink_line``; else the nearest ``Connection X`` declaration
    before ``sink_line``; else the first such declaration in the file.
    """
    src_until_sink = "\n".join(java_src.splitlines()[:sink_line])
    candidates: list[tuple[int, str]] = []
    for m in _CREATE_STMT_RE.finditer(src_until_sink):
        candidates.append((m.start(), m.group("conn")))
    for m in _CONN_DECL_RE.finditer(src_until_sink):
        candidates.append((m.start(), m.group("name")))
    if not candidates:
        # try the whole file
        for m in _CONN_DECL_RE.finditer(java_src):
            candidates.append((m.start(), m.group("name")))
        for m in _CREATE_STMT_RE.finditer(java_src):
            candidates.append((m.start(), m.group("conn")))
    if not candidates:
        return None
    candidates.sort(key=lambda x: -x[0])
    return candidates[0][1]


# --- core entry --------------------------------------------------------------


def synthesize_patch(
    java_src: str,
    slice_: SliceResult,
    plan: PatchPlan,
) -> PatchResult:
    """Apply ``plan`` to ``java_src`` at the location described by ``slice_``."""
    conn = _find_connection(java_src, slice_.sink_call_line)
    if conn is None:
        raise RewriteAbstention("no connection variable in scope")

    # 1) Detect the sink API to know whether to use executeQuery / executeUpdate
    api_match = re.search(
        r"\.\s*(executeQuery|executeUpdate|execute|addBatch)\s*\(",
        slice_.sink_call_text,
    )
    sink_api = api_match.group(1) if api_match else "execute"
    return_void = sink_api in ("executeUpdate", "execute", "addBatch")

    # 2) Build the preparation block. Handle IN-list markers in the template
    template = plan.prepared_template
    expanded_setters: list[SetterCall] = []
    in_list_loops: list[str] = []
    next_param = 1
    for s in plan.setter_calls:
        if s.param_index == -1:
            # IN-list: expand
            tok = f"__INLIST_{s.hole_name}__"
            in_list_loops.append(_emit_in_list_loop(s, next_param, tok))
            # The template-rendering replacement is done after we know
            # how many slots (we keep a placeholder for runtime).
            continue
        # Renumber to preserve textual order
        expanded_setters.append(SetterCall(
            param_index=next_param,
            api=s.api,
            short_method=s.short_method,
            host_expr=s.host_expr,
            hole_name=s.hole_name,
        ))
        next_param += 1

    # 3) Build allow-list guards
    guard_decls: list[str] = []
    for g in plan.allowlist_guards:
        gv = f"__irsam_g_{g.hole_name}"
        guard_decls.append(_emit_guard(g, gv))
        # Substitute the {__GUARD_<name>__} placeholder in the template
        template = template.replace(f"{{__GUARD_{g.hole_name}__}}", '" + ' + gv + ' + "')

    # If there were no guards/inlist tokens, wrap the template literally:
    template_literal = '"' + template.replace('\\', r'\\').replace('"', r'\"') + '"'
    # If we did identifier substitution above, the template literal may
    # already contain unbalanced quotes -- normalize:
    if '+ ' in template:
        # rebuild as Java concatenation expression
        template_literal = '"' + template.replace('"', r'\"') + '"'

    # 4) Compose the new code block
    indent = _detect_indent(java_src, slice_.sink_call_line)
    block_lines: list[str] = []
    block_lines.extend(guard_decls)
    block_lines.append(f"String {_SQL_VAR} = {template_literal};")
    block_lines.append(
        f"java.sql.PreparedStatement {_PS_VAR} = {conn}.prepareStatement({_SQL_VAR});"
    )
    for s in expanded_setters:
        block_lines.append(
            f"{_PS_VAR}.{s.short_method}({s.param_index}, {s.host_expr});"
        )
    block_lines.extend(in_list_loops)

    # 5) Rewrite the sink call: replace ``stmt.executeQuery(sqlVar)`` with
    #    ``__irsam_ps.executeQuery()`` (or executeUpdate)
    new_call = f"{_PS_VAR}.{sink_api}()"
    src_lines = java_src.splitlines(keepends=True)
    sink_idx = slice_.sink_call_line - 1
    original_line = src_lines[sink_idx]
    rewritten_line = original_line.replace(slice_.sink_call_text, new_call)

    indented_block = "\n".join(indent + line for line in block_lines) + "\n"

    # 6) Remove the old SQL variable declaration line(s) if present
    src_lines[sink_idx] = indented_block + rewritten_line
    for decl in slice_.declarations_to_remove:
        for i, line in enumerate(src_lines):
            if line.strip() == decl.strip():
                src_lines[i] = ""
                break

    patched = "".join(src_lines)

    # 7) Ensure imports
    used_imports = ("java.sql.PreparedStatement", "java.sql.SQLException")
    if return_void is False:
        used_imports = used_imports + ("java.sql.ResultSet",)
    patched = _ensure_imports(patched, used_imports)

    diff = "".join(difflib.unified_diff(
        java_src.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile="a/" + "before.java",
        tofile="b/" + "after.java",
        lineterm="",
    ))

    return PatchResult(
        original_source=java_src,
        patched_source=patched,
        unified_diff=diff,
        connection_var=conn,
        used_imports=used_imports,
    )


# --- helpers -----------------------------------------------------------------


def _detect_indent(src: str, line: int) -> str:
    lines = src.splitlines()
    if 0 < line <= len(lines):
        m = re.match(r"[ \t]*", lines[line - 1])
        return m.group(0) if m else ""
    return "        "


def _emit_guard(g: AllowlistGuard, var: str) -> str:
    return (
        f"String {var} = {g.allowlist_java_const}.get({g.host_expr});\n"
        f"if ({var} == null) throw new IllegalArgumentException("
        f"\"IR-SAM: identifier not in allow-list: \" + {g.host_expr});"
    )


def _emit_in_list_loop(s: SetterCall, start_param: int, tok: str) -> str:
    """Emit a Java loop that binds each element of the IN-list argument."""
    return (
        f"java.util.List<?> __irsam_list_{s.hole_name} = "
        f"java.util.Arrays.asList({s.host_expr});\n"
        f"for (int __i = 0; __i < __irsam_list_{s.hole_name}.size(); __i++) {{\n"
        f"    {_PS_VAR}.{s.short_method}({start_param} + __i, "
        f"__irsam_list_{s.hole_name}.get(__i));\n"
        f"}}"
    )


def _ensure_imports(src: str, imports: tuple[str, ...]) -> str:
    """Insert any missing ``import`` statements after the ``package`` line."""
    lines = src.splitlines(keepends=True)
    have = set()
    pkg_idx = -1
    last_import_idx = -1
    for i, line in enumerate(lines):
        if line.startswith("package "):
            pkg_idx = i
        m = re.match(r"\s*import\s+(?:static\s+)?([A-Za-z_][\w.]*);", line)
        if m:
            have.add(m.group(1))
            last_import_idx = i
    missing = [imp for imp in imports if imp not in have]
    if not missing:
        return src
    insert_at = (last_import_idx + 1) if last_import_idx >= 0 else (pkg_idx + 1
                                                                    if pkg_idx >= 0 else 0)
    new_imports = "".join(f"import {imp};\n" for imp in missing)
    if insert_at == 0:
        return new_imports + src
    lines.insert(insert_at, new_imports)
    return "".join(lines)
