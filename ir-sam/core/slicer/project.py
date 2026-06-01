"""Project-level symbol model for global (inter-procedural) slicing.

The intra-procedural slicer (:mod:`core.slicer`) and the one-hop
helper inliner (:mod:`core.slicer.interproc`) both operate on a *single*
compilation unit. To follow tainted data across method *and* file
boundaries (Spring controller -> ``@Autowired`` service -> DAO), the
SDG slicer needs a cheap, text-driven index of the whole project:

* every method (name, owning class, parameters, return type, body), and
* every field (name, declared type, owning class), so that an
  ``@Autowired`` / constructor-injected field call ``this.svc.q(x)``
  can be resolved to a concrete method in another file.

The model is deliberately regex/brace-driven rather than AST-driven so
it shares the robustness profile of the default regex slicer tier and
adds no hard tree-sitter dependency. It is *conservative*: when a name
resolves ambiguously (e.g. an interface with several implementors), the
resolver returns ``None`` and the SDG slicer abstains soundly rather
than guessing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


# --- datatypes ----------------------------------------------------------------


@dataclass(frozen=True)
class MethodDef:
    """One method definition located in the project."""

    name: str
    owner: str                       # simple class name that declares it
    params: tuple[tuple[str, str], ...]  # (param_name, param_type) in order
    return_type: str
    body: str                        # method body WITHOUT the outer braces
    file: Path
    header_line: int                 # 1-based line of the method header
    body_start_line: int             # 1-based line of the first body statement


@dataclass(frozen=True)
class FieldDef:
    """One field declaration (used for injection resolution)."""

    name: str
    declared_type: str               # simple type name (generics stripped)
    owner: str
    injected: bool                   # @Autowired / @Inject / @Resource / ctor


@dataclass(frozen=True)
class ClassDef:
    name: str
    file: Path
    extends: str | None = None
    implements: tuple[str, ...] = ()
    fields: tuple[FieldDef, ...] = ()
    is_interface: bool = False


# --- parsing regexes ----------------------------------------------------------

_CLASS_RE = re.compile(
    r"\b(?P<kind>class|interface)\s+(?P<name>[A-Za-z_]\w*)"
    r"(?:\s*<[^>]*>)?"
    r"(?:\s+extends\s+(?P<ext>[A-Za-z_][\w.]*(?:\s*<[^>]*>)?))?"
    r"(?:\s+implements\s+(?P<impl>[A-Za-z_][\w.,\s<>]*?))?"
    r"\s*\{",
)

_METHOD_RE = re.compile(
    r"""
    (?P<mods>(?:public|protected|private|static|final|abstract|synchronized|native|\s)*)
    (?P<ret>[A-Za-z_][\w.<>,\s\[\]?]*?)\s+
    (?P<name>[A-Za-z_]\w*)\s*
    \((?P<ps>[^;{}]*?)\)\s*
    (?:throws\s+[\w\s,.]+)?\s*\{
    """,
    re.VERBOSE,
)

# Field declarations, optionally preceded by an injection annotation on
# the same or a preceding line. We scan annotations separately.
_FIELD_RE = re.compile(
    r"^\s*(?:(?:public|protected|private|static|final|volatile|transient)\s+)*"
    r"(?P<type>[A-Za-z_][\w.]*(?:\s*<[^>;{}=]*>)?)\s+"
    r"(?P<name>[A-Za-z_]\w*)\s*(?:=[^;]*)?;",
    re.MULTILINE,
)

_INJECT_ANNOS = ("@Autowired", "@Inject", "@Resource", "@Value")

_GENERIC_RE = re.compile(r"<[^>]*>")


def _simple_type(raw: str) -> str:
    """Strip generics / array / qualification down to a simple name."""
    t = _GENERIC_RE.sub("", raw).strip()
    t = t.replace("[]", "").strip()
    if "." in t:
        t = t.rsplit(".", 1)[-1]
    return t


def _matching_brace(src: str, open_idx: int) -> int:
    """Index of the ``}`` matching the ``{`` at ``open_idx`` (string-aware)."""
    depth = 0
    i = open_idx
    n = len(src)
    while i < n:
        c = src[i]
        if c in ('"', "'"):
            i = _skip_str(src, i)
            continue
        if c == "/" and i + 1 < n and src[i + 1] in "/*":
            i = _skip_comment(src, i)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n - 1


def _skip_str(src: str, start: int) -> int:
    quote = src[start]
    i = start + 1
    n = len(src)
    while i < n:
        if src[i] == "\\":
            i += 2
            continue
        if src[i] == quote:
            return i + 1
        i += 1
    return n


def _skip_comment(src: str, start: int) -> int:
    n = len(src)
    if src[start + 1] == "/":
        nl = src.find("\n", start)
        return n if nl < 0 else nl
    end = src.find("*/", start + 2)
    return n if end < 0 else end + 2


# --- model --------------------------------------------------------------------


@dataclass
class ProjectModel:
    """Cross-file index of classes, methods and fields."""

    files: dict[Path, str] = field(default_factory=dict)
    methods_by_name: dict[str, list[MethodDef]] = field(default_factory=dict)
    classes: dict[str, ClassDef] = field(default_factory=dict)

    # ---- construction ----

    @classmethod
    def from_files(cls, sources: dict[Path | str, str]) -> "ProjectModel":
        model = cls()
        for path, src in sources.items():
            model._index_source(Path(path), src)
        return model

    @classmethod
    def from_root(
        cls,
        root: Path | str,
        *,
        files: Iterable[Path] | None = None,
        max_files: int = 5000,
    ) -> "ProjectModel":
        root = Path(root)
        model = cls()
        candidates = list(files) if files is not None else list(
            root.rglob("*.java"))
        for i, p in enumerate(candidates):
            if i >= max_files:
                break
            try:
                src = p.read_text(encoding="utf-8")
            except OSError:
                continue
            model._index_source(p, src)
        return model

    # ---- indexing ----

    def _index_source(self, path: Path, src: str) -> None:
        self.files[path] = src
        for cm in _CLASS_RE.finditer(src):
            cname = cm.group("name")
            ob = src.find("{", cm.start())
            cb = _matching_brace(src, ob)
            body = src[ob + 1:cb]
            implements: tuple[str, ...] = ()
            if cm.group("impl"):
                implements = tuple(
                    _simple_type(x) for x in cm.group("impl").split(",")
                    if x.strip())
            extends = _simple_type(cm.group("ext")) if cm.group("ext") else None
            fields = self._scan_fields(body, cname)
            self.classes[cname] = ClassDef(
                name=cname,
                file=path,
                extends=extends,
                implements=implements,
                fields=fields,
                is_interface=cm.group("kind") == "interface",
            )
            self._scan_methods(src, body, ob + 1, cname, path)

    def _scan_fields(self, class_body: str, owner: str) -> tuple[FieldDef, ...]:
        out: list[FieldDef] = []
        lines = class_body.splitlines()
        # Track injection annotations occurring on preceding lines.
        for fm in _FIELD_RE.finditer(class_body):
            decl_type = _simple_type(fm.group("type"))
            name = fm.group("name")
            # Skip obvious local/keyword false positives.
            if decl_type in {"return", "new", "throw", "else"}:
                continue
            head = class_body[:fm.start()]
            recent = head[-200:]
            injected = any(a in recent for a in _INJECT_ANNOS)
            out.append(FieldDef(
                name=name, declared_type=decl_type, owner=owner,
                injected=injected))
        _ = lines  # retained for future line-accurate diagnostics
        return tuple(out)

    def _scan_methods(
        self, src: str, class_body: str, class_body_offset: int,
        owner: str, path: Path,
    ) -> None:
        for mm in _METHOD_RE.finditer(class_body):
            # absolute brace position in the full source
            rel_brace = class_body.find("{", mm.start())
            abs_brace = class_body_offset + rel_brace
            abs_close = _matching_brace(src, abs_brace)
            body = src[abs_brace + 1:abs_close]
            name = mm.group("name")
            ret = _simple_type(mm.group("ret"))
            if name in {"if", "for", "while", "switch", "catch", "new"}:
                continue
            params = _parse_params(mm.group("ps"))
            header_line = src.count("\n", 0, class_body_offset + mm.start()) + 1
            body_start_line = src.count("\n", 0, abs_brace) + 1
            mdef = MethodDef(
                name=name, owner=owner, params=params, return_type=ret,
                body=body, file=path, header_line=header_line,
                body_start_line=body_start_line)
            self.methods_by_name.setdefault(name, []).append(mdef)

    # ---- resolution ----

    def resolve_method(
        self, name: str, *, owner: str | None = None,
    ) -> MethodDef | None:
        """Resolve a method by name (and optionally declaring class).

        Returns the unique :class:`MethodDef` or ``None`` when the call
        is unresolved or *ambiguous* (the SDG slicer treats ``None`` as
        a sound abstention trigger).
        """
        cands = self.methods_by_name.get(name, [])
        if not cands:
            return None
        if owner is not None:
            owners = self._resolve_concrete_owners(owner)
            scoped = [m for m in cands if m.owner in owners]
            if len(scoped) == 1:
                return scoped[0]
            if len(scoped) > 1:
                return None
            # fall through to unscoped if class hierarchy unknown
        if len(cands) == 1:
            return cands[0]
        return None

    def _resolve_concrete_owners(self, type_name: str) -> set[str]:
        """Map a declared type to the concrete classes that provide it.

        If ``type_name`` is an interface with a single implementor, that
        implementor is returned. Multiple implementors -> empty-ish set
        (ambiguous), handled by the caller as a sound abstention.
        """
        cd = self.classes.get(type_name)
        if cd is not None and not cd.is_interface:
            return {type_name}
        impls = [c.name for c in self.classes.values()
                 if type_name in c.implements or c.extends == type_name]
        if len(impls) == 1:
            return {impls[0]}
        if cd is not None:
            return {type_name}
        return set(impls)

    def field_type(self, owner: str, field_name: str) -> str | None:
        cd = self.classes.get(owner)
        if cd is None:
            return None
        for f in cd.fields:
            if f.name == field_name:
                return f.declared_type
        if cd.extends:
            return self.field_type(cd.extends, field_name)
        return None

    def find_enclosing_class(self, path: Path | str) -> str | None:
        path = Path(path)
        owners = [c.name for c in self.classes.values() if c.file == path]
        return owners[0] if owners else None


def _parse_params(raw: str) -> tuple[tuple[str, str], ...]:
    out: list[tuple[str, str]] = []
    depth = 0
    cur = []
    parts: list[str] = []
    for ch in raw:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur))
    for part in parts:
        p = part.strip()
        if not p:
            continue
        # drop annotations like @RequestParam("x")
        p = re.sub(r"@\w+(?:\([^)]*\))?\s*", "", p).strip()
        p = re.sub(r"\bfinal\b\s*", "", p).strip()
        bits = p.rsplit(maxsplit=1)
        if len(bits) == 2:
            out.append((bits[1], _simple_type(bits[0])))
    return tuple(out)


__all__ = [
    "ProjectModel",
    "MethodDef",
    "FieldDef",
    "ClassDef",
]
