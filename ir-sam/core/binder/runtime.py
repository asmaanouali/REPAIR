"""Catalog-driven binder runtime (Phase 1).

This module replaces the hardcoded JDBC behavior that used to live inside
``core/phi/__init__.py``. The runtime walks a SIG subtree, tries to
match each subtree against the ``pattern`` of every binder declared in
the active :class:`~core.binder.loader.BinderCatalog`, and applies the
matched binder's ``rewrite`` block to produce:

* A rendered template fragment (possibly with ``?`` placeholders or
  ``__INLIST_<hole>__`` markers).
* A set of typed :class:`RewriteOp` operations that Stage F (the
  language-specific rewriter) consumes — setter calls for JDBC, escape
  calls for LDAP/XPath, allow-list guards for identifier holes, IN-list
  loops, etc.

The runtime is deliberately language-agnostic. Stage E (phi) maps the
runtime's ``RewriteOp`` ops onto the language-specific :class:`PatchPlan`
shape; multi-language dispatch (Phase 5) will reuse the same ops to
generate Python / JS / TS edits.

The pattern-matching language is the same nested-dict shape declared in
``schemas/binder.schema.json``. Patterns describe the *kind* of node and
the shape of its ordered children. ``bind: name`` captures a child
subtree under that name so the rewrite template can reference it as
``{name}``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable

from core.iam import Cardinality, Hole, Literal, SemType, SIGNode, SyntCtx

from .loader import Binder, BinderCatalog


# ---------------------------------------------------------------------------
# Output ops
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ParamBindOp:
    """Bind a value-context hole through a catalog-declared parameterizing API.

    Stage F translates this into:
      * Java/JDBC: ``ps.setString(idx, expr)`` / ``setLong`` / ...
      * Python/DB-API: ``params.append(expr)`` then ``cursor.execute(sql, params)``
      * LDAP: ``escape_filter_chars(expr)``
      * XPath: ``$v_<name>`` variable binding (``XPathVariableResolver`` /
        ``lxml.etree.XPath(query, v_name=expr)``).
    """

    hole_name: str
    api: str            # fully qualified API string from the catalog
    host_expr: str      # textual host-language expression for the hole
    param_index: int    # 1-based; -1 means "filled in by rewriter (in-list)"
    cardinality: Cardinality = Cardinality.ONE


@dataclass(frozen=True)
class AllowlistGuardOp:
    """Constrain an identifier-context hole to a developer-supplied allow-list."""

    hole_name: str
    host_expr: str
    allowlist_source: str     # name of the host-language constant
    on_miss: str = "throw_IllegalArgumentException"


@dataclass(frozen=True)
class InListExpandOp:
    """Marker emitted for ``card=many.bounded`` holes.

    Stage F replaces ``__INLIST_<hole>__`` in the rendered template
    with N ``?``-style placeholders and binds each element with the
    parameterizing API the catalog selected for the element's sem.
    """

    hole_name: str
    api: str
    host_expr: str
    element_sem: SemType


# Tagged union of operations the runtime can emit. Stage F dispatches on
# isinstance(op, ...).
RewriteOp = ParamBindOp | AllowlistGuardOp | InListExpandOp


@dataclass(frozen=True)
class BinderMatch:
    """Result of matching one SIG subtree against one binder."""

    binder: Binder
    bindings: dict[str, Any]   # bind name -> SIG sub-element (SIGNode | Hole | Literal)


# ---------------------------------------------------------------------------
# Pattern matcher
# ---------------------------------------------------------------------------


def match_node(pattern: dict[str, Any], node: Any) -> dict[str, Any] | None:
    """Try to match ``node`` against the DSL pattern dict.

    Returns the captured bindings on success, ``None`` on miss. The
    pattern is the nested-dict structure defined by
    ``schemas/binder.schema.json#$defs/pattern_node``.
    """
    bindings: dict[str, Any] = {}
    if not _match_recursive(pattern, node, bindings):
        return None
    return bindings


def _match_recursive(pattern: dict[str, Any], node: Any, bindings: dict[str, Any]) -> bool:
    kind = pattern.get("kind")

    # --- Hole pattern --------------------------------------------------------
    if kind == "Hole":
        if not isinstance(node, Hole):
            return False
        # ctx match
        ctx_p = pattern.get("ctx")
        if ctx_p is not None and node.ctx.value != ctx_p:
            return False
        # sem match (list, OR semantics)
        sem_in = pattern.get("sem_in")
        if sem_in is not None and node.sem.value not in sem_in:
            return False
        # cardinality match
        card_p = pattern.get("card")
        if card_p is not None and node.card.value != card_p:
            return False
        # bind
        bind_name = pattern.get("bind")
        if bind_name:
            bindings[bind_name] = node
        return True

    # --- Token (literal) pattern --------------------------------------------
    if kind == "Token":
        lit = pattern.get("lit")
        if isinstance(node, Literal):
            if lit is not None and node.value.upper() != lit.upper():
                return False
            bind_name = pattern.get("bind")
            if bind_name:
                bindings[bind_name] = node
            return True
        # Some SIGs embed operator/keyword tokens as Literals only.
        return False

    # --- AnyMix wildcard (informational placeholder in some catalogs) ------
    if kind == "AnyMix":
        bind_name = pattern.get("bind")
        if bind_name:
            bindings[bind_name] = node
        return True

    # --- SIGNode pattern (with kind + child shape) --------------------------
    if not isinstance(node, SIGNode):
        return False
    if kind is not None and node.kind != kind:
        return False

    child_patterns = pattern.get("children")
    if child_patterns is not None:
        # Children must match positionally; the pattern length must equal the
        # actual children length for a strict match.
        if len(child_patterns) != len(node.children):
            return False
        for cp, ch in zip(child_patterns, node.children):
            if not _match_recursive(cp, ch, bindings):
                return False

    bind_name = pattern.get("bind")
    if bind_name:
        bindings[bind_name] = node
    return True


def match_binder(catalog: BinderCatalog, node: Any) -> BinderMatch | None:
    """Find the first binder in ``catalog`` whose pattern matches ``node``."""
    for binder in catalog.binders:
        # Only consider ``parameterize`` rewrites here. ``replace_sink`` and
        # ``insert_guard`` operate at a different granularity (whole-sink, not
        # SIG-subtree) and are handled by the language-specific stage F.
        if binder.rewrite_kind != "parameterize":
            continue
        captured = match_node(binder.pattern, node)
        if captured is not None:
            return BinderMatch(binder=binder, bindings=captured)
    return None


# ---------------------------------------------------------------------------
# Setter selection
# ---------------------------------------------------------------------------


# Built-in resolvers per (interpreter, host_language, framework).
# Catalogs MAY override by declaring a static ``api:`` on each binding
# (already supported by the schema); the resolver is only consulted when
# the binding's ``api`` is a macro like ``{{ choose_setter($v.sem) }}``.

_JDBC_SEM_TO_API: dict[SemType, str] = {
    SemType.STRING:  "java.sql.PreparedStatement.setString",
    SemType.INTEGER: "java.sql.PreparedStatement.setLong",
    SemType.DECIMAL: "java.sql.PreparedStatement.setBigDecimal",
    SemType.BOOLEAN: "java.sql.PreparedStatement.setBoolean",
    SemType.DATE:    "java.sql.PreparedStatement.setTimestamp",
    SemType.BLOB:    "java.sql.PreparedStatement.setObject",
    SemType.ENUM:    "java.sql.PreparedStatement.setString",
}


_JDBC_API_TO_SHORT: dict[str, str] = {
    "java.sql.PreparedStatement.setString":     "setString",
    "java.sql.PreparedStatement.setInt":        "setInt",
    "java.sql.PreparedStatement.setLong":       "setLong",
    "java.sql.PreparedStatement.setBigDecimal": "setBigDecimal",
    "java.sql.PreparedStatement.setBoolean":    "setBoolean",
    "java.sql.PreparedStatement.setDate":       "setDate",
    "java.sql.PreparedStatement.setTimestamp":  "setTimestamp",
    "java.sql.PreparedStatement.setObject":     "setObject",
}


def short_method_for_api(api: str) -> str:
    """Return the short method name for a fully-qualified JDBC API string.

    For non-JDBC APIs we fall back to the last dotted segment.
    """
    if api in _JDBC_API_TO_SHORT:
        return _JDBC_API_TO_SHORT[api]
    return api.rsplit(".", 1)[-1]


_MACRO_RE = re.compile(r"\{\{\s*(?P<name>[a-zA-Z_][\w]*)\s*\((?P<args>[^)]*)\)\s*\}\}")


def resolve_api(api_spec: str, catalog: BinderCatalog, hole: Hole) -> str | None:
    """Resolve a binding's ``api`` field, which may be a static value or a macro.

    Returns ``None`` if the macro cannot be resolved for this hole.
    """
    m = _MACRO_RE.match(api_spec.strip())
    if m is None:
        # Static API string.
        return api_spec.strip()

    macro = m.group("name")
    if macro == "choose_setter":
        return _resolve_choose_setter(catalog, hole)
    if macro == "choose_ldap_escape":
        return _resolve_choose_ldap_escape(catalog, hole)
    if macro == "choose_xpath_variable_binding":
        return _resolve_choose_xpath_binding(catalog, hole)
    # Unknown macro — leave unresolved for explicit handling upstream.
    return None


def _resolve_choose_setter(catalog: BinderCatalog, hole: Hole) -> str | None:
    if catalog.interpreter == "sql" and catalog.host_language == "java":
        cand = _JDBC_SEM_TO_API.get(hole.sem)
        if cand and cand in catalog.parameterizing_apis:
            return cand
        # Fall back to setObject when present (guaranteed-safe widening).
        fallback = "java.sql.PreparedStatement.setObject"
        if fallback in catalog.parameterizing_apis:
            return fallback
        return None
    if catalog.interpreter == "sql" and catalog.host_language == "python":
        # DB-API: a single execute() takes the param tuple; the "api" the
        # catalog declares is the execute() entry point, not a setter.
        for api in catalog.parameterizing_apis:
            if api.endswith(".execute") or api.endswith(".executemany"):
                return api
        return None
    return None


def _resolve_choose_ldap_escape(catalog: BinderCatalog, hole: Hole) -> str | None:
    # LDAP "parameterizing" = value escaping per RFC4515. Pick the first
    # framework-appropriate escape helper declared in the catalog.
    fw = (catalog.framework or "").lower()
    preferred: tuple[str, ...]
    if "python" in fw or "ldap3" in fw:
        preferred = (
            "ldap3.utils.conv.escape_filter_chars",
            "ldap.filter.escape_filter_chars",
        )
    else:
        preferred = (
            "org.owasp.esapi.Encoder.encodeForLDAP",
            "org.owasp.esapi.Encoder.encodeForDN",
        )
    for api in preferred:
        if api in catalog.parameterizing_apis:
            return api
    # Fall back to any declared escape helper.
    for api in catalog.parameterizing_apis:
        return api
    return None


def _resolve_choose_xpath_binding(catalog: BinderCatalog, hole: Hole) -> str | None:
    # Prefer setXPathVariableResolver (Java) or lxml's __call__ kwargs.
    preferred = (
        "javax.xml.xpath.XPath.setXPathVariableResolver",
        "lxml.etree.XPath.__call__",
    )
    for api in preferred:
        if api in catalog.parameterizing_apis:
            return api
    for api in catalog.parameterizing_apis:
        return api
    return None


# ---------------------------------------------------------------------------
# Template rendering
# ---------------------------------------------------------------------------


_PLACEHOLDER_RE = re.compile(r"\{([a-zA-Z_][\w.]*)\}")


def render_template(
    template: str,
    bindings: dict[str, Any],
    *,
    render_child: Callable[[Any], str],
    placeholder_token: str,
    inlist_token: Callable[[str], str],
    guard_token: Callable[[str], str],
) -> str:
    """Substitute ``{name}`` placeholders in a binder template_string.

    ``render_child`` is the recursive renderer that turns a captured SIG
    subtree back into source text (used for non-hole captures like
    ``{col}``).

    Specials honored:
      * ``{placeholder}`` -> ``placeholder_token`` (e.g. ``?`` for JDBC,
        ``%s`` for psycopg2, ``:1`` for cx_Oracle).
      * ``{<name>.guarded}`` -> ``guard_token(<name>)`` for identifier
        holes that must be replaced with a Java/Python expression that
        runs the allow-list lookup.
      * ``{<name>.escaped}`` -> the value placeholder for an escape API.
      * ``{argv_list}`` / ``{argv_items}`` -> sentinel for shell argv
        rewrites (Stage F generates the actual list expression).
      * ``{<name>}`` where the captured node is a ``Hole`` -> the
        appropriate placeholder for the hole's cardinality.
    """

    def replace(match: re.Match[str]) -> str:
        token = match.group(1)

        if token == "placeholder":
            return placeholder_token
        if token in ("argv_list", "argv_items"):
            return placeholder_token  # Stage F replaces this token verbatim

        if "." in token:
            name, suffix = token.split(".", 1)
            captured = bindings.get(name)
            if suffix == "guarded":
                return guard_token(name)
            if suffix == "escaped":
                return placeholder_token
            if suffix in ("host_expr", "items"):
                return placeholder_token
            # Unknown suffix: render the captured subtree if present.
            if captured is not None:
                return render_child(captured)
            return match.group(0)

        captured = bindings.get(token)
        if captured is None:
            return match.group(0)
        if isinstance(captured, Hole):
            if captured.ctx is SyntCtx.IDENTIFIER:
                return guard_token(captured.name)
            if captured.card is Cardinality.MANY_BOUNDED:
                return inlist_token(captured.name)
            return placeholder_token
        return render_child(captured)

    return _PLACEHOLDER_RE.sub(replace, template)


# ---------------------------------------------------------------------------
# Convenience: collect rewrite ops from a matched binder
# ---------------------------------------------------------------------------


def collect_ops(
    match: BinderMatch,
    catalog: BinderCatalog,
    *,
    host_exprs: dict[str, str],
    allowlists: dict[str, str],
    param_index: int,
) -> tuple[list[RewriteOp], int]:
    """Produce :class:`RewriteOp` ops from a binder match.

    ``param_index`` is the next 1-based parameter index. The returned
    integer is the new ``param_index`` after this match consumed any
    value-context holes.
    """
    ops: list[RewriteOp] = []
    rewrite = match.binder.rewrite
    declared_bindings: Iterable[dict[str, Any]] = rewrite.get("bindings", []) or ()

    # Build hole-name -> declared binding map by inspecting host_expr macro args.
    by_hole = _bindings_by_hole(declared_bindings, match.bindings)

    for bind_name, captured in match.bindings.items():
        if isinstance(captured, Hole):
            hole = captured
            if hole.ctx is SyntCtx.VALUE:
                spec = by_hole.get(bind_name)
                if spec is None:
                    # No declared binding -> default to first parameterizing API.
                    api = next(iter(catalog.parameterizing_apis), None)
                else:
                    api = resolve_api(spec.get("api", ""), catalog, hole)
                if api is None:
                    raise _RuntimeAbstain(
                        f"value-hole {hole.name!r}: catalog {catalog.id!r} has no API for sem {hole.sem.value!r}"
                    )
                if api not in catalog.parameterizing_apis:
                    raise _RuntimeAbstain(
                        f"value-hole {hole.name!r}: resolved api {api!r} not in parameterizing_apis"
                    )
                host_expr = host_exprs.get(hole.name, "")
                if hole.card is Cardinality.MANY_BOUNDED:
                    ops.append(InListExpandOp(
                        hole_name=hole.name, api=api,
                        host_expr=host_expr, element_sem=hole.sem,
                    ))
                    # IN-list: stage F assigns per-element indices.
                else:
                    ops.append(ParamBindOp(
                        hole_name=hole.name, api=api,
                        host_expr=host_expr, param_index=param_index,
                        cardinality=hole.card,
                    ))
                    param_index += 1
            elif hole.ctx in (SyntCtx.IDENTIFIER, SyntCtx.STRUCTURAL):
                allow = allowlists.get(hole.name)
                if not allow:
                    raise _RuntimeAbstain(
                        f"identifier hole {hole.name!r} has no allow-list"
                    )
                ops.append(AllowlistGuardOp(
                    hole_name=hole.name,
                    host_expr=host_exprs.get(hole.name, ""),
                    allowlist_source=allow,
                    on_miss="throw_IllegalArgumentException",
                ))
            else:
                raise _RuntimeAbstain(
                    f"hole {hole.name!r}: ctx {hole.ctx.value!r} not supported"
                )
    return ops, param_index


def _bindings_by_hole(
    declared: Iterable[dict[str, Any]],
    captured: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Map captured bind-name -> declared binding spec.

    The DSL writes ``host_expr: "$v.host_expr"`` where ``$v`` is the
    captured bind-name of a hole. We extract that to associate the
    declared binding with the hole.
    """
    by_hole: dict[str, dict[str, Any]] = {}
    for spec in declared:
        if not isinstance(spec, dict):
            continue
        target = spec.get("bind_target")
        if target:
            by_hole[target] = spec
            continue
        host_expr = spec.get("host_expr", "")
        m = re.match(r"\$([a-zA-Z_]\w*)", str(host_expr))
        if m:
            by_hole[m.group(1)] = spec
            continue
        # Best-effort: associate with the first hole captured.
        for name, val in captured.items():
            if isinstance(val, Hole) and name not in by_hole:
                by_hole[name] = spec
                break
    return by_hole


class _RuntimeAbstain(Exception):
    """Raised internally by :func:`collect_ops` to signal an abstention.

    Phi catches this and converts it into a :class:`PhiAbstention`.
    """
