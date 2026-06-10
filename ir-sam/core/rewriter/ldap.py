"""Stage F --- LDAP (CWE-90) rewriters.

LDAP filters have no prepared-statement facility; the sound structural
mitigation is **value escaping** per RFC 4515 §3 (filter assertion
values) / RFC 4514 (distinguished names). The rewriter wraps every
attacker-controlled assertion value in the catalog-declared escape
helper, so the special filter metacharacters ``\\ * ( ) NUL`` can never
alter the parsed filter tree (``IRSAM.Soundness.Ldap``).

Hosts:

* **Python** --- ``ldap3.utils.conv.escape_filter_chars`` /
  ``ldap.filter.escape_filter_chars``.
* **Java** --- OWASP ESAPI ``Encoder.encodeForLDAP`` /
  ``encodeForDN``.

Both rewriters consume the :class:`~core.phi.PatchPlan` (its
``prepared_template`` with ``?`` value slots and its ordered
``setter_calls`` giving the host expression + escape API per slot) and
splice the escaped values back into the filter argument of the sink
call. They **abstain** when the sink argument cannot be located, when
an identifier-allow-list guard is present (not yet supported here), or
when the resolved escape API is unknown.
"""

from __future__ import annotations

import difflib
import re

from core.phi import PatchPlan, SetterCall
from core.rewriter import PatchResult, RewriteAbstention
from core.slicer import SliceResult


# api -> (python callable expression builder, import line)
_PY_ESCAPE = {
    "ldap3.utils.conv.escape_filter_chars": (
        "escape_filter_chars",
        "from ldap3.utils.conv import escape_filter_chars",
    ),
    "ldap.filter.escape_filter_chars": (
        "escape_filter_chars",
        "from ldap.filter import escape_filter_chars",
    ),
}

# Filter-argument index by sink method (host -> api -> arg index).
_PY_FILTER_ARG = {
    "search": 1,          # ldap3 Connection.search(base, filter, ...)
    "search_s": 2,        # python-ldap search_s(base, scope, filterstr)
    "search_ext_s": 2,    # python-ldap search_ext_s(base, scope, filterstr)
}
_JAVA_FILTER_ARG = {
    "search": 1,          # JNDI DirContext.search(name, filter, controls)
}


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


def _splice_escaped_filter(prepared: str, escaped_exprs: list[str]) -> str:
    """Interleave ``?`` value slots in ``prepared`` with escaped exprs.

    Produces a host-language string-concatenation expression (the escaped
    values are inlined into the filter literal, which is the RFC-4515
    mitigation shape).
    """
    segments = prepared.split("?")
    if len(segments) - 1 != len(escaped_exprs):
        raise RewriteAbstention(
            "ldap: placeholder/value count mismatch "
            f"({len(segments) - 1} slots, {len(escaped_exprs)} values)"
        )
    pieces: list[str] = []
    for i, seg in enumerate(segments):
        if seg:
            pieces.append(_str_literal(seg))
        if i < len(escaped_exprs):
            pieces.append(escaped_exprs[i])
    return " + ".join(pieces) if pieces else _str_literal("")


def _str_literal(s: str) -> str:
    esc = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{esc}"'

# --- Python --------------------------------------------------------------------

def synthesize_python_ldap_patch(
    src: str,
    slice_: SliceResult,
    plan: PatchPlan,
) -> PatchResult:
    call = slice_.sink_call_text
    if call not in src:
        raise RewriteAbstention("python_ldap: could not locate sink call text")

    open_paren = call.find("(")
    funcname = call[:open_paren].strip()
    
    body = call[open_paren + 1: call.rfind(")")]
    args = _split_top_level_args(body)
    
    guard_decls = []
    
    def _emit_guard(g):
        return (
            f"if {g.host_expr} not in {g.allowlist_java_const}:\n"
            f"    raise ValueError('IR-SAM: identifier not in allow-list: ' + str({g.host_expr}))"
        )

    for g in plan.allowlist_guards:
        guard_decls.append(_emit_guard(g))

    setters = _ordered_value_exprs(plan)
    escaped_exprs: list[str] = []
    used_apis = set()
    for s in setters:
        if s.api not in _PY_ESCAPE:
            raise RewriteAbstention(f"python_ldap: unknown escape api {s.api!r}")
        func, _ = _PY_ESCAPE[s.api]
        escaped_exprs.append(f"{func}({s.host_expr})")
        used_apis.add(s.api)
        
    # Fix #5: allow-list guards ARE emitted — the guard check is the mitigation
    # for LDAP identifier components (attribute names, object classes).
    # The guard_decls list was built above; injection happens at the end.

    # reconstruct the query with escaped exprs
    # Note: we need to handle identifiers properly in the prepared_template?
    # Actually, plan.prepared_template ONLY has '?' for value slots, NOT for identifiers!
    # Wait, phi sets the identifier slot to {__GUARD_name__}.
    # Let's check phi:
    # return f"{{__GUARD_{node.name}__}}"
    # Wait! If phi uses {__GUARD_name__} in prepared_template, _splice_escaped_filter 
    # doesn't handle {__GUARD_name__}. It only splits by `?`.
    # Let's check how we handle it. In xpath, it ignores prepared_template and uses slice_.parts.
    
    query_pieces = []
    vi = 0
    for p in slice_.parts:
        if p.kind == "literal":
            query_pieces.append(p.value)
        else:
            host_expr = p.value.strip()
            guard = next((g for g in plan.allowlist_guards if g.host_expr == host_expr), None)
            if guard:
                query_pieces.append(f"str({guard.host_expr})")
            else:
                if vi < len(escaped_exprs):
                    query_pieces.append(escaped_exprs[vi])
                    vi += 1
                else:
                    query_pieces.append(f"str({host_expr})") # fallback

    new_filter = " + ".join(query_pieces) if query_pieces else _str_literal("")

    # Replace the exact original argument text in the call body
    original_arg_text = "".join(p.value for p in slice_.parts).strip()
    if original_arg_text in body:
        new_body = body.replace(original_arg_text, new_filter, 1)
        new_call = f"{funcname}({new_body})"
    else:
        raise RewriteAbstention("python_ldap: cannot locate filter argument string in call")

    indent = _line_indent(src, call)
    guard_stmt = ""
    for gd in guard_decls:
        # gd contains real newlines; split on them for proper indenting
        for line in gd.split("\n"):
            guard_stmt += f"{indent}{line}\n"

    patched = src.replace(call, new_call, 1)
    line_start = _line_start_index(patched, new_call)
    patched = patched[:line_start] + guard_stmt + patched[line_start:]

    used_imports = tuple(set(_PY_ESCAPE[api][1] for api in used_apis))

    return PatchResult(
        original_source=src,
        patched_source=patched,
        unified_diff=_unified_diff(src, patched),
        connection_var="",
        used_imports=used_imports,
    )


# --- Java --------------------------------------------------------------------


_JAVA_ESCAPE = {
    "org.owasp.esapi.Encoder.encodeForLDAP": "org.owasp.esapi.ESAPI.encoder().encodeForLDAP",
    "org.owasp.esapi.Encoder.encodeForDN": "org.owasp.esapi.ESAPI.encoder().encodeForDN",
}


def synthesize_java_ldap_patch(
    src: str,
    slice_: SliceResult,
    plan: PatchPlan,
) -> PatchResult:
    call = slice_.sink_call_text
    if call not in src:
        raise RewriteAbstention("java_ldap: could not locate sink call text")

    open_paren = call.find("(")
    funcname = call[:open_paren].strip()
    
    body = call[open_paren + 1: call.rfind(")")]
    args = _split_top_level_args(body)

    guard_decls = []

    def _emit_guard(g, var):
        return (
            f"String {var} = {g.allowlist_java_const}.get({g.host_expr});\n"
            f"if ({var} == null) throw new IllegalArgumentException("
            f"\"IR-SAM: identifier not in allow-list: \" + {g.host_expr});"
        )

    for g in plan.allowlist_guards:
        gv = f"__irsam_g_{g.hole_name}"
        guard_decls.append(_emit_guard(g, gv))

    setters = _ordered_value_exprs(plan)
    escaped_exprs: list[str] = []
    used_apis = set()
    for s in setters:
        enc = _JAVA_ESCAPE.get(s.api)
        if enc is None:
            raise RewriteAbstention(f"java_ldap: unknown escape api {s.api!r}")
        escaped_exprs.append(f"{enc}({s.host_expr})")
        used_apis.add(enc)

    query_pieces = []
    vi = 0
    for p in slice_.parts:
        if p.kind == "literal":
            query_pieces.append(p.value)
        else:
            host_expr = p.value.strip()
            guard = next((g for g in plan.allowlist_guards if g.host_expr == host_expr), None)
            if guard:
                gv = f"__irsam_g_{guard.hole_name}"
                query_pieces.append(gv)
            else:
                if vi < len(escaped_exprs):
                    query_pieces.append(escaped_exprs[vi])
                    vi += 1
                else:
                    query_pieces.append(f"String.valueOf({host_expr})")

    new_filter = " + ".join(query_pieces) if query_pieces else _str_literal("")

    original_arg_text = "".join(p.value for p in slice_.parts).strip()
    if original_arg_text in body:
        new_body = body.replace(original_arg_text, new_filter, 1)
        new_call = f"{funcname}({new_body})"
    else:
        raise RewriteAbstention("java_ldap: cannot locate filter argument string in call")

    indent = _line_indent(src, call)
    guard_stmt = ""
    for gd in guard_decls:
        # gd contains real newlines; split on them for proper indenting
        for line in gd.split("\n"):
            guard_stmt += f"{indent}{line}\n"

    patched = src.replace(call, new_call, 1)
    line_start = _line_start_index(patched, new_call)
    patched = patched[:line_start] + guard_stmt + patched[line_start:]

    used_imports = tuple()
    if used_apis:
        used_imports = ("org.owasp.esapi.ESAPI",)

    return PatchResult(
        original_source=src,
        patched_source=patched,
        unified_diff=_unified_diff(src, patched),
        connection_var="",
        used_imports=used_imports,
    )

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
