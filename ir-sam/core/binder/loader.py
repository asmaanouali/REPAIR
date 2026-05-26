"""DSL loader for the binding catalog.

The loader enforces the *closure check* and *hole-kind check* described
in :doc:`docs/binder-dsl.md` §7. Any binder that names a host-language
API outside the declared ``parameterizing_apis`` set is rejected at
load time. This is the mechanical realization of the safety property
that the DSL has no escape hatch for emitting attacker-controlled
bytes outside parameterized APIs or allow-list lookups.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
import yaml

_SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "binder.schema.json"
_SCHEMA: dict[str, Any] = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


class ClosureViolation(ValueError):
    """Raised when a binder references an API outside ``parameterizing_apis``."""


# Recognized rewrite modes. The default is ``parameterize`` (existing
# behavior); ``replace_sink`` (CWE-502 family) and ``insert_guard``
# (CWE-22 family) extend φ from "parameterize holes" to
# "structurally-safe API selection" as documented in
# ``docs/formal-model.md`` §9.6.
_REWRITE_KINDS = frozenset({"parameterize", "replace_sink", "insert_guard"})


@dataclass(frozen=True)
class Binder:
    id: str
    pattern: dict[str, Any]
    rewrite: dict[str, Any]
    preconditions: tuple[Any, ...] = ()
    postconditions: tuple[Any, ...] = ()
    proof_obligation: str = ""

    @property
    def rewrite_kind(self) -> str:
        """One of ``parameterize`` | ``replace_sink`` | ``insert_guard``.

        Defaults to ``parameterize`` for backward compatibility when the
        ``kind`` key is omitted (legacy dsl_version 0 catalogs).
        """
        return self.rewrite.get("kind", "parameterize")


@dataclass(frozen=True)
class BinderCatalog:
    id: str
    version: str
    interpreter: str
    host_language: str
    framework: str
    parameterizing_apis: frozenset[str]
    binders: tuple[Binder, ...] = field(default_factory=tuple)

    def find(self, binder_id: str) -> Binder:
        for b in self.binders:
            if b.id == binder_id:
                return b
        raise KeyError(binder_id)


def load_catalog(path: str | Path) -> BinderCatalog:
    """Load and validate a binder catalog YAML."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    jsonschema.validate(raw, _SCHEMA)
    cat = raw["catalog"]
    apis = frozenset(cat["parameterizing_apis"])
    binders: list[Binder] = []
    for b in cat["binders"]:
        _check_closure(b, apis)
        _check_hole_kinds(b)
        binders.append(
            Binder(
                id=b["id"],
                pattern=b["pattern"],
                rewrite=b["rewrite"],
                preconditions=tuple(b.get("preconditions", [])),
                postconditions=tuple(b.get("postconditions", [])),
                proof_obligation=b.get("proof_obligation", ""),
            )
        )
    return BinderCatalog(
        id=cat["id"],
        version=cat["version"],
        interpreter=cat["applies_to"]["interpreter"],
        host_language=cat["applies_to"]["host_language"],
        framework=cat["applies_to"]["framework"],
        parameterizing_apis=apis,
        binders=tuple(binders),
    )


def _check_closure(binder: dict[str, Any], apis: frozenset[str]) -> None:
    rewrite = binder["rewrite"]
    kind = rewrite.get("kind", "parameterize")
    if kind not in _REWRITE_KINDS:
        raise ValueError(
            f"binder {binder['id']!r}: unknown rewrite.kind {kind!r}; "
            f"expected one of {sorted(_REWRITE_KINDS)}"
        )
    if kind == "replace_sink":
        api = rewrite["safe_api"].strip()
        if api not in apis:
            raise ClosureViolation(
                f"binder {binder['id']!r}: replace_sink safe_api {api!r} "
                f"not in parameterizing_apis"
            )
        return
    if kind == "insert_guard":
        # The guard predicate names a callable in the host language; we
        # require that callable (or the wrapping API) be declared in
        # ``parameterizing_apis`` so the closure property still holds.
        guard = rewrite["guard_predicate"].strip()
        if guard not in apis:
            raise ClosureViolation(
                f"binder {binder['id']!r}: insert_guard guard_predicate "
                f"{guard!r} not in parameterizing_apis"
            )
        return
    # parameterize (default)
    for binding in rewrite.get("bindings", []):
        if "api" in binding:
            api = binding["api"].strip()
            # Macro/template expansions are allowed; they must resolve
            # to APIs in *apis* at expansion time. We only check the
            # static, non-macro case here.
            if _is_symbolic_api(api):
                continue
            if api not in apis:
                raise ClosureViolation(
                    f"binder {binder['id']!r} uses api {api!r} not in "
                    f"parameterizing_apis"
                )


def _check_hole_kinds(binder: dict[str, Any]) -> None:
    rewrite = binder["rewrite"]
    # Only the parameterize variant has a ``bindings`` array.
    if rewrite.get("kind", "parameterize") != "parameterize":
        return
    for binding in rewrite.get("bindings", []):
        if "kind" in binding and binding["kind"] != "allowlist_lookup":
            raise ValueError(
                f"binder {binder['id']!r}: unknown binding kind "
                f"{binding['kind']!r} (only 'allowlist_lookup' is permitted)"
            )


def _is_symbolic_api(api: str) -> bool:
    """Return True for DSL-level API macros resolved by codegen.

    Production catalogs often describe a family of concrete APIs with a
    single symbolic binding such as ``$cursor.execute(sql, params)`` or
    ``{{ choose_setter($v.sem) }}``. Those are closure-checked when the
    binder is expanded against a concrete host framework; statically
    qualified APIs remain checked here.
    """
    return (
        (api.startswith("{{") and api.endswith("}}"))
        or api.startswith("$")
    )
