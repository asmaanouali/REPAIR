"""Per-language pipeline dispatch (Phase 5).

The original :func:`core.pipeline._run_source_at_sink` was hard-wired
to ``(language=java, interpreter=sql)``: the Java regex/AST slicer,
the JDBC ``PreparedStatement`` rewriter, and the
``sql_jdbc.yaml`` binder catalog were all imported directly.

This module introduces a small registry that maps
``(language, interpreter)`` to a :class:`LanguageBackend`. The backend
bundles the four call-points that vary across host languages:

* ``find_sinks(src) -> list[(line, recv, api, call_text)]``
* ``slice_at_sink(src, line) -> SliceResult | SliceAbstention``
* ``synthesize_patch(src, slice_, plan) -> PatchResult``
* ``default_catalog_yaml -> Path`` (binder DSL for this combo)

The pipeline's stages C..E (recon, parse, phi) and stage G (gates) are
language-agnostic and stay shared in ``core.pipeline``.

Two backends are registered by default:

* ``(java, sql)`` — JDBC ``PreparedStatement`` rewrite (legacy MVP).
* ``(python, sql)`` — DB-API parameterized ``cursor.execute`` rewrite.

JS/TS and Python/LDAP/XPath/shell are intentionally NOT registered
yet; the pipeline returns a typed ``unsupported_backend`` abstention
for those tuples until their rewriters land.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Protocol

from core.phi import PatchPlan
from core.recon import ParameterizedTemplate
from core.rewriter import PatchResult
from core.slicer import SliceAbstention, SliceResult


_BINDERS_DIR = Path(__file__).resolve().parents[2] / "binders"


class _FindSinks(Protocol):
    def __call__(self, src: str) -> list[tuple[int, str, str, str]]: ...


class _SliceAtSink(Protocol):
    def __call__(self, src: str, sink_line: int
                 ) -> SliceResult | SliceAbstention: ...


class _Synthesize(Protocol):
    def __call__(self, src: str, slice_: SliceResult, plan: PatchPlan
                 ) -> PatchResult: ...


class _ParseTemplate(Protocol):
    def __call__(self, template: ParameterizedTemplate) -> Any: ...


@dataclass(frozen=True)
class LanguageBackend:
    """All language-specific call-points the pipeline needs."""

    language: str
    interpreter: str
    find_sinks: _FindSinks
    slice_at_sink: _SliceAtSink
    synthesize_patch: _Synthesize
    default_catalog_yaml: Path
    parse_template: Optional[_ParseTemplate] = None


# --- registry ----------------------------------------------------------------


_REGISTRY: dict[tuple[str, str], LanguageBackend] = {}


def register(backend: LanguageBackend) -> None:
    _REGISTRY[(backend.language, backend.interpreter)] = backend


def get_backend(language: str, interpreter: str) -> LanguageBackend | None:
    return _REGISTRY.get((language, interpreter))


def supported_backends() -> tuple[tuple[str, str], ...]:
    return tuple(sorted(_REGISTRY.keys()))


# --- default registrations ---------------------------------------------------


def _register_defaults() -> None:
    # Java / SQL --------------------------------------------------------------
    from core.slicer import find_sink_calls as java_find_sinks
    from core.slicer import slice_sink_argument as java_slice
    from core.rewriter import synthesize_patch as java_synth

    register(LanguageBackend(
        language="java",
        interpreter="sql",
        find_sinks=java_find_sinks,
        slice_at_sink=java_slice,
        synthesize_patch=java_synth,
        default_catalog_yaml=_BINDERS_DIR / "sql_jdbc.yaml",
    ))

    # Java backends (shell/ldap/xpath) ---------------------------------------
    from core.parsers.shell import parse_shell_argv
    from core.parsers.ldap import parse_template_to_sig as parse_ldap
    from core.parsers.xpath import parse_template_to_sig as parse_xpath
    from core.slicer.nonsql import (
        find_java_ldap_sinks,
        find_java_shell_sinks,
        find_java_xpath_sinks,
        slice_java_ldap,
        slice_java_shell,
        slice_java_xpath,
    )
    from core.rewriter.shell import synthesize_java_shell_patch
    from core.rewriter.ldap import synthesize_java_ldap_patch
    from core.rewriter.xpath import synthesize_java_xpath_patch

    register(LanguageBackend(
        language="java",
        interpreter="shell",
        find_sinks=find_java_shell_sinks,
        slice_at_sink=slice_java_shell,
        synthesize_patch=synthesize_java_shell_patch,
        default_catalog_yaml=_BINDERS_DIR / "java_processbuilder.yaml",
        parse_template=parse_shell_argv,
    ))

    register(LanguageBackend(
        language="java",
        interpreter="ldap",
        find_sinks=find_java_ldap_sinks,
        slice_at_sink=slice_java_ldap,
        synthesize_patch=synthesize_java_ldap_patch,
        default_catalog_yaml=_BINDERS_DIR / "ldap_java.yaml",
        parse_template=parse_ldap,
    ))

    register(LanguageBackend(
        language="java",
        interpreter="xpath",
        find_sinks=find_java_xpath_sinks,
        slice_at_sink=slice_java_xpath,
        synthesize_patch=synthesize_java_xpath_patch,
        default_catalog_yaml=_BINDERS_DIR / "xpath_java.yaml",
        parse_template=parse_xpath,
    ))





_register_defaults()

