"""Framework-aware dispatcher (Phase 7).

This module owns Stage A.5 of the IR-SAM pipeline: between sink scan
(Stage A) and slicing (Stage B), we sniff the host source for
framework signals and select the matching binder catalog.

The dispatcher is deliberately heuristic, not magical: it reads a
small allow-list of import patterns and annotation markers. The
selection is observable (`FrameworkProfile.evidence` records which
signals fired) and is fail-soft: if no framework is matched, the
generic `sql_jdbc.yaml` / `sql_pydbapi.yaml` / `sql_jsts.yaml`
catalog is used and the rest of the pipeline proceeds unchanged.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# Static signal sets. Order = priority when multiple frameworks
# match on a single file (most specific first).
_JAVA_FRAMEWORKS: list[tuple[str, list[str], str]] = [
    # (profile_name, regex patterns to look for, binder catalog basename)
    ("spring-jdbctemplate",
     [r"org\.springframework\.jdbc\.core\.(?:JdbcTemplate|NamedParameterJdbcTemplate)",
      r"\bJdbcTemplate\s+\w+",
      r"@Autowired[\s\S]{0,80}JdbcTemplate"],
     "spring_jdbctemplate"),
    ("mybatis",
     [r"org\.apache\.ibatis\.annotations\.(?:Select|Insert|Update|Delete|Param)",
      r"@Select\s*\(",
      r"\$\{[A-Za-z_][\w.]*\}"],
     "mybatis"),
    # JPA is checked before Hibernate so that a `jakarta.persistence`
    # / `javax.persistence` import wins over the generic
    # `.createQuery(` signal that both APIs share.
    ("jpa",
     [r"(?:javax|jakarta)\.persistence\.EntityManager",
      r"(?:javax|jakarta)\.persistence\.Query",
      r"@PersistenceContext",
      r"entityManager\.createQuery"],
     "jpa"),
    ("hibernate-hql",
     [r"org\.hibernate\.Session",
      r"org\.hibernate\.query\.Query",
      r"sessionFactory\.openSession",
      r"\bSessionFactory\b"],
     "hibernate_hql"),
]

_PYTHON_FRAMEWORKS: list[tuple[str, list[str], str]] = [
    ("django-orm",
     [r"\bfrom\s+django\b",
      r"\bimport\s+django\b",
      r"\.objects\.raw\(",
      r"\.extra\s*\(\s*where\s*=",
      r"connection\.cursor\(\)"],
     "django_orm"),
]


@dataclass(frozen=True)
class FrameworkProfile:
    name: str                       # e.g. "spring-jdbctemplate", or "generic"
    catalog_basename: str           # binder YAML basename (no .yaml suffix)
    host_language: str              # "java", "python", "jsts"
    evidence: tuple[str, ...] = ()  # patterns that matched (for audit)

    @property
    def is_framework_aware(self) -> bool:
        return self.name != "generic"


def detect_framework(
    *,
    host_language: str,
    source: str,
    imports: Iterable[str] | None = None,
) -> FrameworkProfile:
    """Return the most specific framework profile for the given source.

    Parameters
    ----------
    host_language : one of "java", "python", "jsts" (matches DSL v0
        ``applies_to.host_language``).
    source        : full source text of the file containing the sink
        (the dispatcher does not need a parsed AST -- it pattern-matches
        on textual signals).
    imports       : optional pre-extracted list of import statements;
        when present these are appended to *source* before scanning so
        callers that already lex imports don't pay for it twice.
    """
    haystack = source if not imports else (source + "\n" + "\n".join(imports))

    table: list[tuple[str, list[str], str]]
    if host_language == "java":
        table = _JAVA_FRAMEWORKS
    elif host_language == "python":
        table = _PYTHON_FRAMEWORKS
    else:
        table = []

    best: FrameworkProfile | None = None
    for name, patterns, basename in table:
        matches = tuple(p for p in patterns if re.search(p, haystack))
        if not matches:
            continue
        # First match wins; the priority order of the table embodies
        # the "most specific first" rule.
        best = FrameworkProfile(
            name=name, catalog_basename=basename,
            host_language=host_language, evidence=matches)
        break

    if best is None:
        # Generic catalogs as fall-through. We pick by host_language.
        fallback = {
            "java":   "sql_jdbc",
            "python": "sql_pydbapi",
        }.get(host_language, "sql_jdbc")
        return FrameworkProfile(
            name="generic", catalog_basename=fallback,
            host_language=host_language, evidence=())
    return best


def catalog_path_for(profile: FrameworkProfile,
                     binders_root: Path | None = None) -> Path:
    """Resolve the binder-catalog YAML path for the chosen profile."""
    if binders_root is None:
        binders_root = Path(__file__).resolve().parents[2] / "binders"
    return binders_root / f"{profile.catalog_basename}.yaml"


# --- framework facts for global slicing --------------------------------------

# Annotations / call shapes that introduce *attacker-controlled* (tainted)
# values at a method boundary. The SDG slicer uses these to anchor the
# backward value-flow: a parameter carrying one of these annotations, or a
# value read through one of these calls, is a taint source.
_JAVA_TAINT_SOURCE_ANNOS = (
    "RequestParam", "PathVariable", "RequestBody", "RequestHeader",
    "CookieValue", "MatrixVariable", "ModelAttribute",
)
_JAVA_TAINT_SOURCE_CALLS = (
    r"\bgetParameter\s*\(", r"\bgetParameterValues\s*\(",
    r"\bgetHeader\s*\(", r"\bgetQueryString\s*\(",
    r"\bgetParameterMap\s*\(",
)

# Mapping/entry-point annotations -- these mark request handlers, i.e. the
# top of a cross-file flow. Useful as evidence that the file is a web entry.
_JAVA_ENTRY_ANNOS = (
    "GetMapping", "PostMapping", "PutMapping", "DeleteMapping",
    "PatchMapping", "RequestMapping", "RestController", "Controller",
)


@dataclass(frozen=True)
class FrameworkFacts:
    """Slicing-relevant facts extracted from a single source file.

    ``tainted_params`` lists parameter names annotated as request inputs
    (e.g. ``@RequestParam String name`` -> ``"name"``). ``taint_calls``
    records receiver-free taint-source call shapes that appeared. These
    feed the SDG taint roots and the IAM symbol environment Sigma so a
    cross-file-confirmed tainted value is flagged for disambiguation.
    """

    framework: str
    tainted_params: tuple[str, ...] = ()
    taint_calls: tuple[str, ...] = ()
    is_web_entry: bool = False
    evidence: tuple[str, ...] = ()


_PARAM_ANNO_RE = re.compile(
    r"@(?P<anno>" + "|".join(_JAVA_TAINT_SOURCE_ANNOS) + r")\b"
    r"(?:\s*\([^)]*\))?\s+"
    r"(?:final\s+)?[A-Za-z_][\w.<>\[\]]*\s+"
    r"(?P<name>[A-Za-z_]\w*)",
)


def extract_facts(*, host_language: str, source: str) -> FrameworkFacts:
    """Extract taint sources / entry-point markers for global slicing.

    Pure-text and fail-soft: an empty :class:`FrameworkFacts` (no
    tainted params) is a safe default that simply makes the SDG slicer
    more conservative.
    """
    profile = detect_framework(host_language=host_language, source=source)
    if host_language != "java":
        return FrameworkFacts(framework=profile.name)

    tainted: list[str] = []
    evidence: list[str] = []
    for m in _PARAM_ANNO_RE.finditer(source):
        tainted.append(m.group("name"))
        evidence.append("@" + m.group("anno"))

    taint_calls: list[str] = []
    for pat in _JAVA_TAINT_SOURCE_CALLS:
        if re.search(pat, source):
            taint_calls.append(pat.strip("\\b").rstrip(r"\s*\("))

    is_entry = any(("@" + a) in source for a in _JAVA_ENTRY_ANNOS)

    return FrameworkFacts(
        framework=profile.name,
        tainted_params=tuple(dict.fromkeys(tainted)),
        taint_calls=tuple(dict.fromkeys(taint_calls)),
        is_web_entry=is_entry,
        evidence=tuple(dict.fromkeys(evidence)),
    )


__all__ = [
    "FrameworkProfile",
    "FrameworkFacts",
    "detect_framework",
    "extract_facts",
    "catalog_path_for",
]
