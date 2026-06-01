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


# --- Python ------------------------------------------------------------------


def synthesize_python_ldap_patch(
    src: str,
    slice_: SliceResult,
    plan: PatchPlan,
) -> PatchResult:
    if plan.allowlist_guards:
        raise RewriteAbstention(
            "python_ldap: identifier allow-list guards not yet supported"
        )
    call = slice_.sink_call_text
    if call not in src:
        raise RewriteAbstention("python_ldap: could not locate sink call text")

    open_paren = call.find("(")
    funcname = call[:open_paren].strip()
    method = funcname.rsplit(".", 1)[-1]
    arg_idx = _PY_FILTER_ARG.get(method)
    if arg_idx is None:
        raise RewriteAbstention(f"python_ldap: unsupported sink method {method!r}")

    body = call[open_paren + 1: call.rfind(")")]
    args = _split_top_level_args(body)
    if arg_idx >= len(args):
        raise RewriteAbstention("python_ldap: filter argument not found")

    setters = _ordered_value_exprs(plan)
    imports: list[str] = []
    escaped_exprs: list[str] = []
    for s in setters:
        spec = _PY_ESCAPE.get(s.api)
        if spec is None:
            raise RewriteAbstention(f"python_ldap: unknown escape api {s.api!r}")
        fn, imp = spec
        escaped_exprs.append(f"{fn}({s.host_expr})")
        if imp not in imports:
            imports.append(imp)

    new_filter = _splice_escaped_filter(plan.prepared_template, escaped_exprs)
    args[arg_idx] = new_filter
    new_call = f"{funcname}(" + ", ".join(args) + ")"

    patched = src.replace(call, new_call, 1)
    for imp in imports:
        patched = _ensure_python_import(patched, imp)

    return PatchResult(
        original_source=src,
        patched_source=patched,
        unified_diff=_unified_diff(src, patched),
        connection_var="",
        used_imports=tuple(imports),
    )


def _ensure_python_import(src: str, import_line: str) -> str:
    if re.search(rf"(?m)^\s*{re.escape(import_line)}\s*$", src):
        return src
    return import_line + "\n" + src


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
    if plan.allowlist_guards:
        raise RewriteAbstention(
            "java_ldap: identifier allow-list guards not yet supported"
        )
    call = slice_.sink_call_text
    if call not in src:
        raise RewriteAbstention("java_ldap: could not locate sink call text")

    open_paren = call.find("(")
    funcname = call[:open_paren].strip()
    method = funcname.rsplit(".", 1)[-1]
    arg_idx = _JAVA_FILTER_ARG.get(method)
    if arg_idx is None:
        raise RewriteAbstention(f"java_ldap: unsupported sink method {method!r}")

    body = call[open_paren + 1: call.rfind(")")]
    args = _split_top_level_args(body)
    if arg_idx >= len(args):
        raise RewriteAbstention("java_ldap: filter argument not found")

    setters = _ordered_value_exprs(plan)
    escaped_exprs: list[str] = []
    for s in setters:
        enc = _JAVA_ESCAPE.get(s.api)
        if enc is None:
            raise RewriteAbstention(f"java_ldap: unknown escape api {s.api!r}")
        escaped_exprs.append(f"{enc}({s.host_expr})")

    new_filter = _splice_escaped_filter(plan.prepared_template, escaped_exprs)
    args[arg_idx] = new_filter
    new_call = f"{funcname}(" + ", ".join(args) + ")"

    patched = src.replace(call, new_call, 1)
    return PatchResult(
        original_source=src,
        patched_source=patched,
        unified_diff=_unified_diff(src, patched),
        connection_var="",
        used_imports=("org.owasp.esapi.ESAPI",),
    )
